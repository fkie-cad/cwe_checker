use crate::abstract_domain::*;
use crate::analysis::function_signature::AccessPattern;
use crate::analysis::function_signature::FunctionSignature;
use crate::analysis::graph::Graph;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::*;
use std::collections::{BTreeMap, BTreeSet};

use super::object::AbstractObject;
use super::state::State;
use super::{Config, Data, VERSION};

/// Contains methods of the `Context` struct that deal with the manipulation of abstract IDs.
mod id_manipulation;
/// Methods and functions for handling extern symbol stubs.
mod stubs;
/// Contains trait implementations for the `Context` struct,
/// especially the implementation of the [`forward_interprocedural_fixpoint::Context`](crate::analysis::forward_interprocedural_fixpoint::Context) trait.
mod trait_impls;

/// Contains all context information needed for the pointer inference fixpoint computation.
///
/// The struct also implements the [`forward_interprocedural_fixpoint::Context`](crate::analysis::forward_interprocedural_fixpoint::Context) trait to enable the fixpoint computation.
pub struct Context<'a> {
    /// The program control flow graph on which the fixpoint will be computed
    pub graph: &'a Graph<'a>,
    /// A reference to the `Project` object representing the binary
    pub project: &'a Project,
    /// Maps the TIDs of functions that shall be treated as extern symbols to the `ExternSymbol` object representing it.
    pub extern_symbol_map: &'a BTreeMap<Tid, ExternSymbol>,
    /// Maps the TIDs of internal functions to the function signatures computed for it.
    pub fn_signatures: &'a BTreeMap<Tid, FunctionSignature>,
    /// Maps the names of stubbed extern symbols to the corresponding function signatures.
    pub extern_fn_param_access_patterns: BTreeMap<&'static str, Vec<AccessPattern>>,
    /// A channel where found CWE warnings and log messages should be sent to.
    /// The receiver may filter or modify the warnings before presenting them to the user.
    /// For example, the same CWE warning will be found several times
    /// if the fixpoint computation does not instantly stabilize at the corresponding code point.
    /// These duplicates need to be filtered out.
    pub log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    /// Names of `malloc`-like extern functions.
    pub allocation_symbols: Vec<String>,
}

impl<'a> Context<'a> {
    /// Create a new context object for a given project.
    /// Also needs two channels as input to know where CWE warnings and log messages should be sent to.
    pub fn new(
        analysis_results: &'a AnalysisResults<'a>,
        config: Config,
        log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    ) -> Context<'a> {
        Context {
            graph: analysis_results.control_flow_graph,
            project: analysis_results.project,
            extern_symbol_map: &analysis_results.project.program.term.extern_symbols,
            fn_signatures: analysis_results.function_signatures.unwrap(),
            extern_fn_param_access_patterns:
                crate::analysis::function_signature::stubs::generate_param_access_stubs(),
            log_collector,
            allocation_symbols: config.allocation_symbols,
        }
    }

    /// Return `true` if the all of the following properties hold:
    /// * The CPU architecture is a MIPS variant and `var` is the MIPS global pointer register `gp`
    /// * Loading the value at `address` into the register `var` would overwrite the value of `var` with a `Top` value.
    fn is_mips_gp_load_to_top_value(
        &self,
        state: &State,
        var: &Variable,
        address: &Expression,
    ) -> bool {
        if self.project.cpu_architecture.contains("MIPS") && var.name == "gp" {
            if let Ok(gp_val) =
                state.load_value(address, var.size, &self.project.runtime_memory_image)
            {
                gp_val.is_top()
            } else {
                true
            }
        } else {
            false
        }
    }

    /// If `result` is an `Err`, log the error message as a debug message through the `log_collector` channel.
    pub fn log_debug(&self, result: Result<(), Error>, location: Option<&Tid>) {
        if let Err(err) = result {
            let mut log_message =
                LogMessage::new_debug(format!("{err}")).source("Pointer Inference");
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
        match state_before_return
            .get_register(&self.project.stack_pointer_register)
            .get_if_unique_target()
        {
            Some((id, offset))
                if *id == state_before_return.stack_id
                    && *offset == expected_stack_pointer_offset.into() =>
            {
                Ok(())
            }
            _ => Err(anyhow!("Unexpected stack register value on return")),
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
        let address_bytesize = self.project.get_pointer_bytesize();

        match extern_symbol.get_unique_return_register() {
            Ok(return_register) => {
                let object_id = AbstractIdentifier::new(
                    call.tid.clone(),
                    AbstractLocation::from_var(return_register).unwrap(),
                );
                state.memory.add_abstract_object(
                    object_id.clone(),
                    address_bytesize,
                    Some(super::object::ObjectType::Heap),
                );
                let pointer = Data::from_target(
                    object_id,
                    Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
                );
                state.set_register(return_register, pointer);
                state
            }
            Err(err) => {
                // We cannot track the new object, since we do not know where to store the pointer to it.
                self.log_debug(Err(err), Some(&call.tid));
                state
            }
        }
    }

    /// Check whether the jump is an indirect call whose target evaluates to a *Top* value in the given state.
    fn is_indirect_call_with_top_target(&self, state: &State, call: &Term<Jmp>) -> bool {
        match &call.term {
            Jmp::CallInd { target, .. } => state.eval(target).is_top(),
            _ => false,
        }
    }

    /// Adjust the stack register after a call to a function.
    ///
    /// On x86, this removes the return address from the stack
    /// (other architectures pass the return address in a register, not on the stack).
    /// On other architectures the stack register retains the value it had before the call.
    /// Note that in some calling conventions the callee also clears function parameters from the stack.
    /// We do not detect and handle these cases yet.
    fn adjust_stack_register_on_return_from_call(
        &self,
        state_before_call: &State,
        new_state: &mut State,
    ) {
        let stack_register = &self.project.stack_pointer_register;
        let stack_pointer = state_before_call.get_register(stack_register);
        match self.project.cpu_architecture.as_str() {
            "x86" | "x86_32" | "x86_64" => {
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
    /// Basically, we assume that the call may write to all memory objects and registers that is has access to.
    fn handle_generic_extern_call(
        &self,
        state: &State,
        mut new_state: State,
        call: &Term<Jmp>,
        extern_symbol: &ExternSymbol,
    ) -> State {
        self.log_debug(
            new_state.clear_stack_parameter(extern_symbol, &self.project.runtime_memory_image),
            Some(&call.tid),
        );
        let calling_conv = self.project.get_calling_convention(extern_symbol);
        let mut possible_referenced_ids = BTreeSet::new();
        if extern_symbol.parameters.is_empty() && extern_symbol.return_values.is_empty() {
            // We assume here that we do not know the parameters and approximate them by all possible parameter registers.
            // This approximation is wrong if the function is known but has neither parameters nor return values.
            // We cannot distinguish these two cases yet.
            for parameter_register in calling_conv.integer_parameter_register.iter() {
                let register_value = state.get_register(parameter_register);
                possible_referenced_ids.extend(register_value.referenced_ids().cloned());
            }
            for float_parameter_expression in calling_conv.float_parameter_register.iter() {
                let register_value = state.eval(float_parameter_expression);
                possible_referenced_ids.extend(register_value.referenced_ids().cloned());
            }
        } else {
            for parameter in extern_symbol.parameters.iter() {
                if let Ok(data) =
                    state.eval_parameter_arg(parameter, &self.project.runtime_memory_image)
                {
                    possible_referenced_ids.extend(data.referenced_ids().cloned());
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
            self.adjust_stack_register_on_return_from_call(state_before_call, &mut new_state);

            let mut possible_referenced_ids = BTreeSet::new();
            for parameter_register in calling_conv.integer_parameter_register.iter() {
                let register_value = state_before_call.get_register(parameter_register);
                possible_referenced_ids.extend(register_value.referenced_ids().cloned());
            }
            for float_parameter_expression in calling_conv.float_parameter_register.iter() {
                let register_value = state_before_call.eval(float_parameter_expression);
                possible_referenced_ids.extend(register_value.referenced_ids().cloned());
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

    /// Report a NULL dereference CWE at the address of the given TID.
    fn report_null_deref(&self, tid: &Tid) {
        let warning = CweWarning {
            name: "CWE476".to_string(),
            version: VERSION.to_string(),
            addresses: vec![tid.address.clone()],
            tids: vec![format!("{tid}")],
            symbols: Vec::new(),
            other: Vec::new(),
            description: format!(
                "(NULL Pointer Dereference) Memory access at {} may result in a NULL dereference",
                tid.address
            ),
        };
        let _ = self.log_collector.send(LogThreadMsg::Cwe(warning));
    }

    /// Merge global memory data from the callee global memory object to the caller global memory object
    /// if the corresponding global variable is marked as mutable in both the caller and callee.
    fn merge_global_mem_from_callee(
        &self,
        caller_state: &mut State,
        callee_global_mem: &AbstractObject,
        replacement_map: &BTreeMap<AbstractIdentifier, Data>,
        callee_fn_sig: &FunctionSignature,
        call_tid: &Tid,
    ) {
        let caller_global_mem_id = caller_state.get_global_mem_id();
        let caller_fn_sig = self.fn_signatures.get(caller_state.get_fn_tid()).unwrap();
        let caller_global_mem = caller_state
            .memory
            .get_object_mut(&caller_global_mem_id)
            .unwrap();

        // Get the intervals corresponding to global variables
        // and the access pattern that denotes which globals should be overwritten by callee data.
        let intervals =
            compute_call_return_global_var_access_intervals(caller_fn_sig, callee_fn_sig);

        let mut caller_mem_region = caller_global_mem.get_mem_region().clone();
        mark_values_in_caller_global_mem_as_potentially_overwritten(
            &mut caller_mem_region,
            &intervals,
        );

        // Insert values from the callee into the memory object.
        let mut referenced_ids = BTreeSet::new();
        for (index, value) in callee_global_mem.get_mem_region().iter() {
            if let Some((_interval_start, access_pattern)) =
                intervals.range(..((*index + 1) as u64)).last()
            {
                if access_pattern.is_mutably_dereferenced() {
                    let mut value = value.clone();
                    value.replace_all_ids(replacement_map);
                    referenced_ids.extend(value.referenced_ids().cloned());
                    caller_mem_region.insert_at_byte_index(value, *index);
                }
            } else {
                self.log_debug(
                    Err(anyhow!("Unexpected occurrence of global variables.")),
                    Some(call_tid),
                );
            }
        }

        caller_global_mem.overwrite_mem_region(caller_mem_region);
        caller_global_mem.add_ids_to_pointer_targets(referenced_ids);
    }
}

/// Generate a list of global indices as a union of the global indices known to caller and callee.
/// The corresponding access patterns are mutably derefenced
/// if and only if they are mutably dereferenced in both the caller and the callee.
///
/// Note that each index is supposed to denote the interval from that index until the next index in the map.
/// This is a heuristic approximation, since we do not know the actual sizes of the global variables here.
fn compute_call_return_global_var_access_intervals(
    caller_fn_sig: &FunctionSignature,
    callee_fn_sig: &FunctionSignature,
) -> BTreeMap<u64, AccessPattern> {
    let mut intervals: BTreeMap<u64, AccessPattern> = caller_fn_sig
        .global_parameters
        .keys()
        .chain(callee_fn_sig.global_parameters.keys())
        .map(|index| (*index, AccessPattern::new()))
        .collect();
    for (index, access_pattern) in intervals.iter_mut() {
        if let (Some(caller_pattern), Some(callee_pattern)) = (
            caller_fn_sig.global_parameters.get(index),
            callee_fn_sig.global_parameters.get(index),
        ) {
            if caller_pattern.is_mutably_dereferenced() && callee_pattern.is_mutably_dereferenced()
            {
                access_pattern.set_mutably_dereferenced_flag();
            }
        }
    }

    intervals
}

/// Mark all values in the caller memory object representing global memory,
/// that may have been overwritten by the callee, as potential `Top` values.
fn mark_values_in_caller_global_mem_as_potentially_overwritten(
    caller_global_mem_region: &mut MemRegion<Data>,
    access_intervals: &BTreeMap<u64, AccessPattern>,
) {
    let mut interval_iter = access_intervals.iter().peekable();
    while let Some((index, access_pattern)) = interval_iter.next() {
        if access_pattern.is_mutably_dereferenced() {
            if let Some((next_index, _next_pattern)) = interval_iter.peek() {
                caller_global_mem_region.mark_interval_values_as_top(
                    *index as i64,
                    (**next_index - 1) as i64,
                    ByteSize::new(1),
                );
            } else {
                caller_global_mem_region.mark_interval_values_as_top(
                    *index as i64,
                    std::i64::MAX - 1,
                    ByteSize::new(1),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
