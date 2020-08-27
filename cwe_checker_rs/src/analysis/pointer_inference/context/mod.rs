use crate::abstract_domain::*;
use crate::analysis::graph::Graph;
use crate::bil::Expression;
use crate::prelude::*;
use crate::term::symbol::ExternSymbol;
use crate::term::*;
use crate::utils::log::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::state::State;
use super::{Data, VERSION};

/// Contains all context information needed for the pointer inference fixpoint computation.
pub struct Context<'a> {
    /// The program control flow graph on which the fixpoint will be computed
    pub graph: Graph<'a>,
    /// A reference to the `Project` object representing the binary
    pub project: &'a Project,
    /// Maps the TIDs of functions that shall be treated as extern symbols to the `ExternSymbol` object representing it.
    pub extern_symbol_map: BTreeMap<Tid, &'a ExternSymbol>,
    /// A channel where found CWE warnings should be sent to.
    /// The receiver may filter or modify the warnings before presenting them to the user.
    /// For example, the same CWE warning will be found several times
    /// if the fixpoint computation does not instantly stabilize at the corresponding code point.
    /// These duplicates need to be filtered out.
    pub cwe_collector: crossbeam_channel::Sender<CweWarning>,
    /// A channel where log messages should be sent to.
    pub log_collector: crossbeam_channel::Sender<LogMessage>,
}

impl<'a> Context<'a> {
    /// Create a new context object for a given project.
    /// Also needs two channels as input to know where CWE warnings and log messages should be sent to.
    pub fn new(
        project: &Project,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
        log_collector: crossbeam_channel::Sender<LogMessage>,
    ) -> Context {
        let mut extern_symbol_map = BTreeMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }
        let extern_symbol_tid_set: HashSet<Tid> = project
            .program
            .term
            .extern_symbols
            .iter()
            .map(|symb| symb.tid.clone())
            .collect();
        let graph =
            crate::analysis::graph::get_program_cfg(&project.program, extern_symbol_tid_set);
        Context {
            graph,
            project,
            extern_symbol_map,
            cwe_collector,
            log_collector,
        }
    }

    /// If `result` is an `Err`, log the error message as a debug message through the `log_collector` channel.
    pub fn log_debug<'_lt>(&self, result: Result<(), Error>, location: Option<&'_lt Tid>) {
        if let Err(err) = result {
            let log_message = LogMessage {
                text: format!("Pointer Inference: {}", err),
                level: LogLevel::Debug,
                location: location.cloned(),
            };
            self.log_collector.send(log_message).unwrap();
        }
    }

    /// Detect and log if the stack pointer is not as expected when returning from a function.
    fn detect_stack_pointer_information_loss_on_return(
        &self,
        state_before_return: &State,
        return_term: &Term<Jmp>,
    ) {
        let expected_stack_pointer_offset = match self.project.cpu_architecture.as_str() {
            "x86" | "x86_64" => Bitvector::from_u16(self.project.get_pointer_bitsize() / 8)
                .into_zero_extend(self.project.get_pointer_bitsize() as usize)
                .unwrap(),
            _ => Bitvector::zero((self.project.get_pointer_bitsize() as usize).into()),
        };
        match state_before_return.get_register(&self.project.stack_pointer_register) {
            Ok(Data::Pointer(pointer)) => {
                if pointer.targets().len() == 1 {
                    let (id, offset) = pointer.targets().iter().next().unwrap();
                    if *id != state_before_return.stack_id
                        || *offset != expected_stack_pointer_offset.into()
                    {
                        self.log_debug(
                            Err(anyhow!(
                                "Unexpected stack register value at return instruction"
                            )),
                            Some(&return_term.tid),
                        );
                    }
                }
            }
            Ok(Data::Top(_)) => self.log_debug(
                Err(anyhow!(
                    "Stack register value lost during function execution"
                )),
                Some(&return_term.tid),
            ),
            Ok(Data::Value(_)) => self.log_debug(
                Err(anyhow!("Unexpected stack register value on return")),
                Some(&return_term.tid),
            ),
            Err(err) => self.log_debug(Err(err), Some(&return_term.tid)),
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
    ) -> Option<State> {
        match extern_symbol.get_unique_return_register() {
            Ok(return_register) => {
                let object_id = AbstractIdentifier::new(
                    call.tid.clone(),
                    AbstractLocation::from_var(return_register).unwrap(),
                );
                let address_bitsize = self.project.stack_pointer_register.bitsize().unwrap();
                state.memory.add_abstract_object(
                    object_id.clone(),
                    Bitvector::zero((address_bitsize as usize).into()).into(),
                    super::object::ObjectType::Heap,
                    address_bitsize,
                );
                let pointer = PointerDomain::new(
                    object_id,
                    Bitvector::zero((address_bitsize as usize).into()).into(),
                );
                self.log_debug(
                    state.set_register(return_register, pointer.into()),
                    Some(&call.tid),
                );
                Some(state)
            }
            Err(err) => {
                // We cannot track the new object, since we do not know where to store the pointer to it.
                self.log_debug(Err(err), Some(&call.tid));
                Some(state)
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
    ) -> Option<State> {
        match extern_symbol.get_unique_parameter() {
            Ok(parameter_expression) => match state.eval(parameter_expression) {
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
                            self.cwe_collector.send(warning).unwrap();
                        }
                    } else {
                        self.log_debug(
                            Err(anyhow!("Free on a non-pointer value called.")),
                            Some(&call.tid),
                        );
                    }
                    new_state.remove_unreferenced_objects();
                    Some(new_state)
                }
                Err(err) => {
                    self.log_debug(Err(err), Some(&call.tid));
                    Some(new_state)
                }
            },
            Err(err) => {
                // We do not know which memory object to free
                self.log_debug(Err(err), Some(&call.tid));
                Some(new_state)
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
        for argument in extern_symbol
            .arguments
            .iter()
            .filter(|arg| arg.intent.is_input())
        {
            match state.eval(&argument.location) {
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
                        self.cwe_collector.send(warning).unwrap();
                    }
                }
                Err(err) => self.log_debug(
                    Err(err.context(format!(
                        "Function argument expression {:?} could not be evaluated",
                        argument.location
                    ))),
                    Some(&call.tid),
                ),
            }
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
    ) -> Option<State> {
        self.log_debug(
            new_state.clear_stack_parameter(extern_symbol),
            Some(&call.tid),
        );
        let mut possible_referenced_ids = BTreeSet::new();
        if extern_symbol.arguments.is_empty() {
            // TODO: We assume here that we do not know the parameters and approximate them by all parameter registers.
            // This approximation is wrong if the function is known but has neither parameters nor return values.
            // We need to somehow distinguish these two cases.
            for parameter_register_name in self.project.parameter_registers.iter() {
                if let Some(register_value) = state.get_register_by_name(parameter_register_name) {
                    possible_referenced_ids.append(&mut register_value.referenced_ids());
                }
            }
        } else {
            for parameter in extern_symbol
                .arguments
                .iter()
                .filter(|arg| arg.intent.is_input())
            {
                if let Ok(data) = state.eval(&parameter.location) {
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
        Some(new_state)
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
                    BitvectorDomain::new_top(stack_pointer.bitsize())
                }
            } else {
                BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
            }
        } else {
            BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
        }
    }
}

impl<'a> crate::analysis::interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the underlying graph on which the analysis operates.
    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    /// Merge two state values.
    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    /// Update the state according to the effects of the given `Def` term.
    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        // first check for use-after-frees
        if state.contains_access_of_dangling_memory(&def.term.rhs) {
            let warning = CweWarning {
                name: "CWE416".to_string(),
                version: VERSION.to_string(),
                addresses: vec![def.tid.address.clone()],
                tids: vec![format!("{}", def.tid)],
                symbols: Vec::new(),
                other: Vec::new(),
                description: format!(
                    "(Use After Free) Access through a dangling pointer at {}",
                    def.tid.address
                ),
            };
            self.cwe_collector.send(warning).unwrap();
        }

        match &def.term.rhs {
            Expression::IfThenElse {
                condition,
                true_exp,
                false_exp,
            } => {
                // IfThenElse needs special handling, because it may encode conditional store instructions.
                let mut true_state = state.clone();
                if let Expression::Store { .. } = **true_exp {
                    self.log_debug(true_state.handle_store_exp(true_exp), Some(&def.tid));
                } else {
                    self.log_debug(
                        true_state.handle_register_assign(&def.term.lhs, true_exp),
                        Some(&def.tid),
                    );
                };
                let mut false_state = state.clone();
                if let Expression::Store { .. } = **false_exp {
                    self.log_debug(false_state.handle_store_exp(false_exp), Some(&def.tid));
                } else {
                    self.log_debug(
                        false_state.handle_register_assign(&def.term.lhs, false_exp),
                        Some(&def.tid),
                    );
                };
                match state.eval(condition) {
                    Ok(Data::Value(cond)) if !cond.is_top() => {
                        if cond == Bitvector::from_bit(true).into() {
                            Some(true_state)
                        } else if cond == Bitvector::from_bit(false).into() {
                            Some(false_state)
                        } else {
                            panic!("IfThenElse with wrong condition bitsize encountered")
                        }
                    }
                    Ok(_) => Some(true_state.merge(&false_state)),
                    Err(err) => panic!("IfThenElse-Condition evaluation failed: {}", err),
                }
            }
            Expression::Store { .. } => {
                let mut state = state.clone();
                self.log_debug(state.handle_store_exp(&def.term.rhs), Some(&def.tid));
                Some(state)
            }
            expression => {
                let mut new_state = state.clone();
                self.log_debug(
                    new_state.handle_register_assign(&def.term.lhs, expression),
                    Some(&def.tid),
                );
                Some(new_state)
            }
        }
    }

    /// Update the state according to the effects of the given `Jmp` term.
    /// Right now this only removes virtual registers from the state,
    /// as specialization for conditional jumps is not implemented yet.
    fn update_jump(
        &self,
        value: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        let mut new_value = value.clone();
        new_value.remove_virtual_register();
        Some(new_value)
    }

    /// Update the state according to the effects of the given `Call` term.
    /// The resulting state is the state at the start of the call target function.
    fn update_call(
        &self,
        state: &State,
        call_term: &Term<Jmp>,
        _target_node: &crate::analysis::graph::Node,
    ) -> Option<State> {
        let call = if let JmpKind::Call(ref call) = call_term.term.kind {
            call
        } else {
            panic!("Malformed control flow graph: Encountered call edge with a non-call jump term.")
        };

        if let Label::Direct(ref callee_tid) = call.target {
            let callee_stack_id = AbstractIdentifier::new(
                callee_tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let new_caller_stack_id = AbstractIdentifier::new(
                call_term.tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let stack_offset_adjustment = self.get_current_stack_offset(state);
            let address_bitsize = self.project.stack_pointer_register.bitsize().unwrap();

            let mut callee_state = state.clone();
            callee_state.remove_virtual_register();
            // Replace the caller stack ID with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id to avoid confusing caller and callee stack ids in case of recursive calls.
            callee_state.replace_abstract_id(
                &state.stack_id,
                &new_caller_stack_id,
                &stack_offset_adjustment,
            );
            // add a new memory object for the callee stack frame
            callee_state.memory.add_abstract_object(
                callee_stack_id.clone(),
                Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap()).into(),
                super::object::ObjectType::Stack,
                address_bitsize,
            );
            // set the new stack_id
            callee_state.stack_id = callee_stack_id.clone();
            // Set the stack pointer register to the callee stack id.
            // At the beginning of a function this is the only known pointer to the new stack frame.
            self.log_debug(
                callee_state.set_register(
                    &self.project.stack_pointer_register,
                    PointerDomain::new(
                        callee_stack_id.clone(),
                        Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap())
                            .into(),
                    )
                    .into(),
                ),
                Some(&call_term.tid),
            );
            // set the list of caller stack ids to only this caller id
            callee_state.caller_stack_ids = BTreeSet::new();
            callee_state.caller_stack_ids.insert(new_caller_stack_id);
            // Remove non-referenced objects and objects, only the caller knows about, from the state.
            callee_state.ids_known_to_caller = BTreeSet::new();
            callee_state.remove_unreferenced_objects();
            // all remaining objects, except for the callee stack id, are also known to the caller
            callee_state.ids_known_to_caller = callee_state.memory.get_all_object_ids();
            callee_state.ids_known_to_caller.remove(&callee_stack_id);

            Some(callee_state)
        } else {
            panic!("Indirect call edges not yet supported.")
        }
    }

    /// Update the state according to the effects of the given return instruction.
    /// The `state_before_call` is used to reconstruct caller-specific information like the caller stack frame.
    fn update_return(
        &self,
        state_before_return: &State,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
    ) -> Option<State> {
        // TODO: For the long term we may have to replace the IDs representing callers with something
        // that identifies the edge of the call and not just the callsite.
        // When indirect calls are handled, the callsite alone is not a unique identifier anymore.
        // This may lead to confusion if both caller and callee have the same ID in their respective caller_stack_id sets.

        // we only return to functions with a value before the call to prevent returning to dead code
        let state_before_call = match state_before_call {
            Some(value) => value,
            None => return None,
        };
        let original_caller_stack_id = &state_before_call.stack_id;
        let caller_stack_id = AbstractIdentifier::new(
            call_term.tid.clone(),
            AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
        );
        let callee_stack_id = &state_before_return.stack_id;
        let stack_offset_on_call = self.get_current_stack_offset(state_before_call);

        // Detect possible information loss on the stack pointer and report it.
        self.detect_stack_pointer_information_loss_on_return(state_before_return, return_term);

        // Check whether state_before_return actually knows the `caller_stack_id`.
        // If not, we are returning from a state that cannot correspond to this callsite.
        if !state_before_return
            .caller_stack_ids
            .contains(&caller_stack_id)
        {
            return None;
        }

        let mut state_after_return = state_before_return.clone();
        state_after_return.remove_virtual_register();
        // Remove the IDs of other callers not corresponding to this call
        state_after_return.remove_other_caller_stack_ids(&caller_stack_id);

        state_after_return.replace_abstract_id(
            &caller_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call.clone()),
        );
        state_after_return.merge_callee_stack_to_caller_stack(
            callee_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call),
        );
        state_after_return.stack_id = original_caller_stack_id.clone();
        state_after_return.caller_stack_ids = state_before_call.caller_stack_ids.clone();
        state_after_return.ids_known_to_caller = state_before_call.ids_known_to_caller.clone();

        state_after_return.readd_caller_objects(state_before_call);

        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();

        Some(state_after_return)
    }

    /// Update the state according to the effect of a call to an extern symbol.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut new_state = state.clone();
        let call_target = match &call.term.kind {
            JmpKind::Call(call_inner) => &call_inner.target,
            _ => panic!("Malformed control flow graph encountered."),
        };
        // Clear non-callee-saved registers from the state.
        new_state.clear_non_callee_saved_register(&self.project.callee_saved_registers[..]);
        // On x86, remove the return address from the stack (other architectures pass the return address in a register, not on the stack).
        // Note that in some calling conventions the callee also clears function parameters from the stack.
        // We do not detect and handle these cases yet.
        let stack_register = &self.project.stack_pointer_register;
        let stack_pointer = state.get_register(stack_register).unwrap();
        match self.project.cpu_architecture.as_str() {
            "x86" | "x86_64" => {
                let offset = Bitvector::from_u16(stack_register.bitsize().unwrap() / 8)
                    .into_zero_extend(stack_register.bitsize().unwrap() as usize)
                    .unwrap();
                self.log_debug(
                    new_state.set_register(
                        stack_register,
                        stack_pointer.bin_op(crate::bil::BinOpType::PLUS, &offset.into()),
                    ),
                    Some(&call.tid),
                );
            }
            _ => self.log_debug(
                new_state.set_register(stack_register, stack_pointer),
                Some(&call.tid),
            ),
        }

        match call_target {
            Label::Direct(tid) => {
                if let Some(extern_symbol) = self.extern_symbol_map.get(tid) {
                    // Check parameter for possible use-after-frees
                    self.check_parameter_register_for_dangling_pointer(state, call, extern_symbol);

                    match extern_symbol.name.as_str() {
                        "malloc" | "calloc" | "realloc" | "xmalloc" => self
                            .add_new_object_in_call_return_register(new_state, call, extern_symbol),
                        "free" => self.mark_parameter_object_as_freed(
                            state,
                            new_state,
                            call,
                            extern_symbol,
                        ),
                        _ => self.handle_generic_extern_call(state, new_state, call, extern_symbol),
                    }
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            Label::Indirect(_) => unimplemented!("Handling of indirect edges not yet implemented"), // Right now this case should not exist. Decide how to handle only after it can actually occur.
        }
    }

    /// Update the state with the knowledge that some conditional evaluated to true or false.
    /// Currently not implemented, this function just returns the state as it is.
    fn specialize_conditional(
        &self,
        value: &State,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<State> {
        Some(value.clone())
    }
}

#[cfg(test)]
mod tests;
