use super::object::ObjectType;
use crate::analysis::graph::Graph;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::*;
use crate::{abstract_domain::*, utils::binary::RuntimeMemoryImage};
use std::collections::{BTreeMap, BTreeSet};

use super::state::State;
use super::{Config, Data, VERSION};

// contains trait implementations for the `Context` struct,
// especially the implementation of the `interprocedural_fixpoint::Context` trait.
mod trait_impls;

/// Contains all context information needed for the pointer inference fixpoint computation.
///
/// The struct also implements the `interprocedural_fixpoint::Context` trait to enable the fixpoint computation.
pub struct Context<'a> {
    /// The program control flow graph on which the fixpoint will be computed
    pub graph: &'a Graph<'a>,
    /// A reference to the `Project` object representing the binary
    pub project: &'a Project,
    /// The runtime memory image for reading global read-only variables.
    /// Note that values of writeable global memory segments are not tracked.
    pub runtime_memory_image: &'a RuntimeMemoryImage,
    /// Maps the TIDs of functions that shall be treated as extern symbols to the `ExternSymbol` object representing it.
    pub extern_symbol_map: BTreeMap<Tid, &'a ExternSymbol>,
    /// A channel where found CWE warnings and log messages should be sent to.
    /// The receiver may filter or modify the warnings before presenting them to the user.
    /// For example, the same CWE warning will be found several times
    /// if the fixpoint computation does not instantly stabilize at the corresponding code point.
    /// These duplicates need to be filtered out.
    pub log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    /// Names of `malloc`-like extern functions.
    pub allocation_symbols: Vec<String>,
    /// Names of `free`-like extern functions.
    pub deallocation_symbols: Vec<String>,
}

impl<'a> Context<'a> {
    /// Create a new context object for a given project.
    /// Also needs two channels as input to know where CWE warnings and log messages should be sent to.
    pub fn new(
        project: &'a Project,
        runtime_memory_image: &'a RuntimeMemoryImage,
        control_flow_graph: &'a Graph<'a>,
        config: Config,
        log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    ) -> Context<'a> {
        let mut extern_symbol_map = BTreeMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }
        Context {
            graph: control_flow_graph,
            project,
            runtime_memory_image,
            extern_symbol_map,
            log_collector,
            allocation_symbols: config.allocation_symbols,
            deallocation_symbols: config.deallocation_symbols,
        }
    }

    /// If `result` is an `Err`, log the error message as a debug message through the `log_collector` channel.
    pub fn log_debug(&self, result: Result<(), Error>, location: Option<&Tid>) {
        if let Err(err) = result {
            let mut log_message =
                LogMessage::new_debug(format!("{}", err)).source("Pointer Inference");
            if let Some(loc) = location {
                log_message = log_message.location(loc.clone());
            };
            let _ = self.log_collector.send(LogThreadMsg::Log(log_message));
        }
    }

    /// Detect and log if the stack pointer is not as expected when returning from a function.
    fn detect_stack_pointer_information_loss_on_return(
        &self,
        state_before_return: &State,
    ) -> Result<(), Error> {
        let expected_stack_pointer_offset = match self.project.cpu_architecture.as_str() {
            "x86" | "x86_32" | "x86_64" => {
                Bitvector::from_u64(u64::from(self.project.get_pointer_bytesize()))
                    .into_truncate(apint::BitWidth::from(self.project.get_pointer_bytesize()))
                    .unwrap()
            }
            _ => Bitvector::zero(apint::BitWidth::from(self.project.get_pointer_bytesize())),
        };
        match state_before_return.get_register(&self.project.stack_pointer_register) {
            Ok(Data::Pointer(pointer)) => {
                if pointer.targets().len() == 1 {
                    let (id, offset) = pointer.targets().iter().next().unwrap();
                    if *id != state_before_return.stack_id
                        || *offset != expected_stack_pointer_offset.into()
                    {
                        Err(anyhow!("Unexpected stack register value on return"))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(anyhow!(
                        "Unexpected number of stack register targets on return"
                    ))
                }
            }
            Ok(Data::Top(_)) => Err(anyhow!(
                "Stack register value lost during function execution"
            )),
            Ok(Data::Value(_)) => Err(anyhow!("Unexpected stack register value on return")),
            Err(err) => Err(err),
        }
    }

    /// Add a new abstract object and a pointer to it in the return register of an extern call.
    /// This models the behaviour of `malloc`-like functions,
    /// except that we cannot represent possible `NULL` pointers as return values yet.
    fn add_new_object_in_call_return_register(
        &self,
        mut state: State,
        call: &Term<Jmp>,
        extern_symbol: &ExternSymbol,
    ) -> State {
        match extern_symbol.get_unique_return_register() {
            Ok(return_register) => {
                let object_id = AbstractIdentifier::new(
                    call.tid.clone(),
                    AbstractLocation::from_var(return_register).unwrap(),
                );
                let address_bytesize = self.project.get_pointer_bytesize();
                state.memory.add_abstract_object(
                    object_id.clone(),
                    Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
                    super::object::ObjectType::Heap,
                    address_bytesize,
                );
                let pointer = PointerDomain::new(
                    object_id,
                    Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
                );
                state.set_register(return_register, pointer.into());
                state
            }
            Err(err) => {
                // We cannot track the new object, since we do not know where to store the pointer to it.
                self.log_debug(Err(err), Some(&call.tid));
                state
            }
        }
    }

    /// Mark the object that the parameter of a call is pointing to as freed.
    /// If the object may have been already freed, generate a CWE warning.
    /// This models the behaviour of `free` and similar functions.
    fn mark_parameter_object_as_freed(
        &self,
        state: &State,
        mut new_state: State,
        call: &Term<Jmp>,
        extern_symbol: &ExternSymbol,
    ) -> State {
        match extern_symbol.get_unique_parameter() {
            Ok(parameter) => {
                let parameter_value = state.eval_parameter_arg(
                    parameter,
                    &self.project.stack_pointer_register,
                    &self.runtime_memory_image,
                );
                match parameter_value {
                    Ok(memory_object_pointer) => {
                        if let Data::Pointer(pointer) = memory_object_pointer {
                            if let Err(possible_double_frees) =
                                new_state.mark_mem_object_as_freed(&pointer)
                            {
                                let warning = CweWarning {
                                    name: "CWE415".to_string(),
                                    version: VERSION.to_string(),
                                    addresses: vec![call.tid.address.clone()],
                                    tids: vec![format!("{}", call.tid)],
                                    symbols: Vec::new(),
                                    other: vec![possible_double_frees
                                        .into_iter()
                                        .map(|(id, err)| format!("{}: {}", id, err))
                                        .collect()],
                                    description: format!(
                                        "(Double Free) Object may have been freed before at {}",
                                        call.tid.address
                                    ),
                                };
                                let _ = self.log_collector.send(LogThreadMsg::Cwe(warning));
                            }
                        } else {
                            self.log_debug(
                                Err(anyhow!("Free on a non-pointer value called.")),
                                Some(&call.tid),
                            );
                        }
                        new_state.remove_unreferenced_objects();
                        new_state
                    }
                    Err(err) => {
                        self.log_debug(Err(err), Some(&call.tid));
                        new_state
                    }
                }
            }
            Err(err) => {
                // We do not know which memory object to free
                self.log_debug(Err(err), Some(&call.tid));
                new_state
            }
        }
    }

    /// Check all parameter registers of a call for dangling pointers and report possible use-after-frees.
    fn check_parameter_register_for_dangling_pointer(
        &self,
        state: &State,
        call: &Term<Jmp>,
        extern_symbol: &ExternSymbol,
    ) {
        for parameter in extern_symbol.parameters.iter() {
            match state.eval_parameter_arg(
                parameter,
                &self.project.stack_pointer_register,
                &self.runtime_memory_image,
            ) {
                Ok(value) => {
                    if state.memory.is_dangling_pointer(&value, true) {
                        let warning = CweWarning {
                            name: "CWE416".to_string(),
                            version: VERSION.to_string(),
                            addresses: vec![call.tid.address.clone()],
                            tids: vec![format!("{}", call.tid)],
                            symbols: Vec::new(),
                            other: Vec::new(),
                            description: format!(
                                "(Use After Free) Call to {} may access freed memory at {}",
                                extern_symbol.name, call.tid.address
                            ),
                        };
                        let _ = self.log_collector.send(LogThreadMsg::Cwe(warning));
                    }
                }
                Err(err) => self.log_debug(
                    Err(err.context(format!(
                        "Function parameter {:?} could not be evaluated",
                        parameter
                    ))),
                    Some(&call.tid),
                ),
            }
        }
    }

    /// Check whether the jump is an indirect call whose target evaluates to a *Top* value in the given state.
    fn is_indirect_call_with_top_target(&self, state: &State, call: &Term<Jmp>) -> bool {
        match &call.term {
            Jmp::CallInd { target, .. }
                if state.eval(target).map_or(false, |value| value.is_top()) =>
            {
                true
            }
            _ => false,
        }
    }

    /// Adjust the stack register after a call to an extern function.
    ///
    /// On x86, this removes the return address from the stack
    /// (other architectures pass the return address in a register, not on the stack).
    /// On other architectures the stack register retains the value it had before the call.
    /// Note that in some calling conventions the callee also clears function parameters from the stack.
    /// We do not detect and handle these cases yet.
    fn adjust_stack_register_on_extern_call(
        &self,
        state_before_call: &State,
        new_state: &mut State,
    ) {
        let stack_register = &self.project.stack_pointer_register;
        let stack_pointer = state_before_call.get_register(stack_register).unwrap();
        match self.project.cpu_architecture.as_str() {
            "x86" | "x86_64" => {
                let offset = Bitvector::from_u64(stack_register.size.into())
                    .into_truncate(apint::BitWidth::from(stack_register.size))
                    .unwrap();
                new_state.set_register(
                    stack_register,
                    stack_pointer.bin_op(BinOpType::IntAdd, &offset.into()),
                );
            }
            _ => new_state.set_register(stack_register, stack_pointer),
        }
    }

    /// Handle an extern symbol call, whose concrete effect on the state is unknown.
    /// Basically, we assume that the call may write to all memory objects and register that is has access to.
    fn handle_generic_extern_call(
        &self,
        state: &State,
        mut new_state: State,
        call: &Term<Jmp>,
        extern_symbol: &ExternSymbol,
    ) -> State {
        self.log_debug(
            new_state.clear_stack_parameter(
                extern_symbol,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ),
            Some(&call.tid),
        );
        let calling_conv = extern_symbol.get_calling_convention(&self.project);
        let mut possible_referenced_ids = BTreeSet::new();
        if extern_symbol.parameters.is_empty() && extern_symbol.return_values.is_empty() {
            // We assume here that we do not know the parameters and approximate them by all possible parameter registers.
            // This approximation is wrong if the function is known but has neither parameters nor return values.
            // We cannot distinguish these two cases yet.
            for parameter_register_name in calling_conv.parameter_register.iter() {
                if let Some(register_value) = state.get_register_by_name(parameter_register_name) {
                    possible_referenced_ids.append(&mut register_value.referenced_ids());
                }
            }
        } else {
            for parameter in extern_symbol.parameters.iter() {
                if let Ok(data) = state.eval_parameter_arg(
                    parameter,
                    &self.project.stack_pointer_register,
                    &self.runtime_memory_image,
                ) {
                    possible_referenced_ids.append(&mut data.referenced_ids());
                }
            }
        }
        possible_referenced_ids =
            state.add_recursively_referenced_ids_to_id_set(possible_referenced_ids);
        // Delete content of all referenced objects, as the function may write to them.
        for id in possible_referenced_ids.iter() {
            new_state
                .memory
                .assume_arbitrary_writes_to_object(id, &possible_referenced_ids);
        }
        new_state
    }

    /// Handle a generic call whose target function is unknown.
    ///
    /// This function just assumes that the target of the call uses a reasonable standard calling convention
    /// and that it may access (and write to) all parameter registers of this calling convention.
    /// We also assume that the function does not use any parameters saved on the stack,
    /// which may greatly reduce correctness of the analysis for the x86_32 architecture.
    fn handle_call_to_generic_unknown_function(&self, state_before_call: &State) -> Option<State> {
        if let Some(calling_conv) = self.project.get_standard_calling_convention() {
            let mut new_state = state_before_call.clone();
            new_state.clear_non_callee_saved_register(&calling_conv.callee_saved_register[..]);
            // Adjust stack register value (for x86 architecture).
            self.adjust_stack_register_on_extern_call(state_before_call, &mut new_state);

            let mut possible_referenced_ids = BTreeSet::new();
            for parameter_register_name in calling_conv.parameter_register.iter() {
                if let Some(register_value) =
                    state_before_call.get_register_by_name(parameter_register_name)
                {
                    possible_referenced_ids.append(&mut register_value.referenced_ids());
                }
            }
            possible_referenced_ids =
                state_before_call.add_recursively_referenced_ids_to_id_set(possible_referenced_ids);
            // Delete content of all referenced objects, as the function may write to them.
            for id in possible_referenced_ids.iter() {
                new_state
                    .memory
                    .assume_arbitrary_writes_to_object(id, &possible_referenced_ids);
            }
            Some(new_state)
        } else {
            None // We don't try to handle cases where we cannot guess a reasonable standard calling convention.
        }
    }

    /// Get the offset of the current stack pointer to the base of the current stack frame.
    fn get_current_stack_offset(&self, state: &State) -> BitvectorDomain {
        if let Ok(Data::Pointer(ref stack_pointer)) =
            state.get_register(&self.project.stack_pointer_register)
        {
            if stack_pointer.targets().len() == 1 {
                let (stack_id, stack_offset_domain) =
                    stack_pointer.targets().iter().next().unwrap();
                if *stack_id == state.stack_id {
                    stack_offset_domain.clone()
                } else {
                    BitvectorDomain::new_top(stack_pointer.bytesize())
                }
            } else {
                BitvectorDomain::new_top(self.project.stack_pointer_register.size)
            }
        } else {
            BitvectorDomain::new_top(self.project.stack_pointer_register.size)
        }
    }
}

#[cfg(test)]
mod tests;
