use super::object::ObjectType;
use crate::abstract_domain::*;
use crate::analysis::graph::Graph;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

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
    /// Names of `malloc`-like extern functions.
    pub allocation_symbols: Vec<String>,
    /// Names of `free`-like extern functions.
    pub deallocation_symbols: Vec<String>,
}

impl<'a> Context<'a> {
    /// Create a new context object for a given project.
    /// Also needs two channels as input to know where CWE warnings and log messages should be sent to.
    pub fn new(
        project: &Project,
        config: Config,
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
            allocation_symbols: config.allocation_symbols,
            deallocation_symbols: config.deallocation_symbols,
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
            "x86" | "x86_64" => Bitvector::from_u64(u64::from(self.project.get_pointer_bytesize()))
                .into_truncate(apint::BitWidth::from(self.project.get_pointer_bytesize()))
                .unwrap(),
            _ => Bitvector::zero(apint::BitWidth::from(self.project.get_pointer_bytesize())),
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
                Some(state)
            }
            Err(err) => {
                // We cannot track the new object, since we do not know where to store the pointer to it.
                self.log_debug(Err(err), Some(&call.tid));
                Some(state)
            }
        }
    }

    /// Evaluate the value of a parameter of an extern symbol for the given state.
    fn eval_parameter_arg(&self, state: &State, parameter: &Arg) -> Result<Data, Error> {
        match parameter {
            Arg::Register(var) => state.eval(&Expression::Var(var.clone())),
            Arg::Stack { offset, size } => state.load_value(
                &Expression::BinOp {
                    op: BinOpType::IntAdd,
                    lhs: Box::new(Expression::Var(self.project.stack_pointer_register.clone())),
                    rhs: Box::new(Expression::Const(
                        Bitvector::from_i64(*offset)
                            .into_truncate(apint::BitWidth::from(
                                self.project.get_pointer_bytesize(),
                            ))
                            .unwrap(),
                    )),
                },
                *size,
            ),
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
            Ok(parameter) => {
                let parameter_value = self.eval_parameter_arg(state, parameter);
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
                }
            }
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
        for parameter in extern_symbol.parameters.iter() {
            match self.eval_parameter_arg(state, parameter) {
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
                        "Function parameter {:?} could not be evaluated",
                        parameter
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
            new_state.clear_stack_parameter(extern_symbol, &self.project.stack_pointer_register),
            Some(&call.tid),
        );
        let mut possible_referenced_ids = BTreeSet::new();
        if extern_symbol.parameters.is_empty() && extern_symbol.return_values.is_empty() {
            // We assume here that we do not know the parameters and approximate them by all possible parameter registers.
            // This approximation is wrong if the function is known but has neither parameters nor return values.
            // We cannot distinguish these two cases yet.
            for parameter_register_name in self.project.parameter_registers.iter() {
                if let Some(register_value) = state.get_register_by_name(parameter_register_name) {
                    possible_referenced_ids.append(&mut register_value.referenced_ids());
                }
            }
        } else {
            for parameter in extern_symbol.parameters.iter() {
                if let Ok(data) = self.eval_parameter_arg(state, parameter) {
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
