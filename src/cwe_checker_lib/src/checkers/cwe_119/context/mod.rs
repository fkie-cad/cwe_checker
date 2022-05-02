use crate::abstract_domain::*;
use crate::analysis::function_signature::FunctionSignature;
use crate::analysis::graph::Graph;
use crate::analysis::pointer_inference::{Data, PointerInference};
use crate::intermediate_representation::*;
use crate::utils::log::{CweWarning, LogMessage, LogThreadMsg};
use crate::{analysis::vsa_results::VsaResult, prelude::*};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::state::State;

/// Trait implementations for the [`Context`] struct,
/// especially the implementation of the [forward interprocedural fixpoint context](`crate::analysis::forward_interprocedural_fixpoint::Context`) trait.
mod trait_impls;

/// The context struct for the analysis.
pub struct Context<'a> {
    /// A pointer to the project struct.
    pub project: &'a Project,
    /// A pointer to the control flow graph.
    pub graph: &'a Graph<'a>,
    /// A pointer to the results of the pointer inference analysis.
    pub pointer_inference: &'a PointerInference<'a>,
    /// A pointer to the computed function signatures for all internal functions.
    pub function_signatures: &'a BTreeMap<Tid, FunctionSignature>,
    /// A map mapping the TID of  a function to the set of all known callsites of that function.
    pub callee_to_callsites_map: HashMap<Tid, HashSet<Tid>>,
    /// A map that maps abstract identifiers representing the values of parameters at callsites
    /// to the corresponding value (in the context of the caller) according to the pointer inference analysis.
    pub param_replacement_map: HashMap<AbstractIdentifier, Data>,
    /// A map that maps the TIDs of calls to allocatingfunctions (like malloc, realloc and calloc)
    /// to the value representing the size of the allocated memory object according to the pointer inference analysis.
    pub malloc_tid_to_object_size_map: HashMap<Tid, Data>,
    /// A map that maps the TIDs of jump instructions to the function TID of the caller.
    pub call_to_caller_fn_map: HashMap<Tid, Tid>,
    /// A sender channel that can be used to collect logs in the corresponding logging thread.
    pub log_collector: crossbeam_channel::Sender<LogThreadMsg>,
}

impl<'a> Context<'a> {
    /// Create a new context object.
    pub fn new<'b>(
        analysis_results: &'b AnalysisResults<'a>,
        log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    ) -> Context<'a>
    where
        'a: 'b,
    {
        let project = analysis_results.project;
        Context {
            project,
            graph: analysis_results.control_flow_graph,
            pointer_inference: analysis_results.pointer_inference.unwrap(),
            function_signatures: analysis_results.function_signatures.unwrap(),
            callee_to_callsites_map: compute_callee_to_call_sites_map(project),
            param_replacement_map: compute_param_replacement_map(analysis_results),
            malloc_tid_to_object_size_map: compute_size_values_of_malloc_calls(analysis_results),
            call_to_caller_fn_map: compute_call_to_caller_map(project),
            log_collector,
        }
    }

    /// Returns `true` if the given abstract ID is the identifier of a stack frame of some function.
    pub fn is_stack_frame_id(&self, id: &AbstractIdentifier) -> bool {
        self.project.program.term.subs.contains_key(id.get_tid())
            && *id
                == AbstractIdentifier::from_var(
                    id.get_tid().clone(),
                    &self.project.stack_pointer_register,
                )
    }

    /// Compute the size of a heap object created by a malloc-like function call.
    ///
    /// Uses the path hints in the given `object_id` to concretize the size if possible.
    /// If the size may be unknown but at least one possible absolute value for the size is found,
    /// then the absolute value is used and unknown origins of the size value are ignored.
    /// If more than one possible absolute value for the size is found then the minimum value for the size is returned.
    pub fn compute_size_of_heap_object(&self, object_id: &AbstractIdentifier) -> BitvectorDomain {
        if let Some(object_size) = self.malloc_tid_to_object_size_map.get(object_id.get_tid()) {
            let fn_tid_at_malloc_call = self.call_to_caller_fn_map[object_id.get_tid()].clone();
            let object_size = self.recursively_substitute_param_values_context_sensitive(
                object_size,
                &fn_tid_at_malloc_call,
                object_id.get_path_hints(),
            );
            let object_size = self.recursively_substitute_param_values(&object_size);
            let object_size = match object_size.get_absolute_value() {
                Some(size) => {
                    if let Ok((lower_bound, upper_bound)) = size.try_to_offset_interval() {
                        // If the lower bound is a reasonable value we approximate the object size by the lower bound instead of the upper bound.
                        let bound = if lower_bound > 0 {
                            lower_bound
                        } else {
                            upper_bound
                        };
                        Bitvector::from_i64(bound)
                            .into_resize_signed(object_size.bytesize())
                            .into()
                    } else {
                        BitvectorDomain::new_top(object_size.bytesize())
                    }
                }
                None => BitvectorDomain::new_top(object_size.bytesize()),
            };
            object_size
        } else {
            BitvectorDomain::new_top(object_id.bytesize())
        }
    }

    /// Merge all possible caller values for the given parameter ID.
    /// The absolute values also merged separately to prevent widening operations during the merge.
    fn substitute_param_values(
        &self,
        param_id: &AbstractIdentifier,
    ) -> (Option<IntervalDomain>, Data) {
        let mut merged_absolute_value: Option<IntervalDomain> = None;
        let mut merged_data: Option<Data> = None;
        let function_tid = param_id.get_tid();
        if let Some(callsites) = self.callee_to_callsites_map.get(function_tid) {
            for callsite in callsites {
                let param_id_at_callsite =
                    AbstractIdentifier::new(callsite.clone(), param_id.get_location().clone());
                let value_at_callsite = match self.param_replacement_map.get(&param_id_at_callsite)
                {
                    Some(val) => val,
                    None => continue,
                };
                merged_absolute_value = match (
                    &merged_absolute_value,
                    value_at_callsite.get_absolute_value(),
                ) {
                    (Some(val_left), Some(val_right)) => Some(val_left.signed_merge(val_right)),
                    (Some(val), None) | (None, Some(val)) => Some(val.clone()),
                    (None, None) => None,
                };
                merged_data = merged_data
                    .map(|val| val.merge(value_at_callsite))
                    .or_else(|| Some(value_at_callsite.clone()));
            }
        }
        let merged_data = merged_data.unwrap_or_else(|| Data::new_top(param_id.bytesize()));
        (merged_absolute_value, merged_data)
    }

    /// Recursively merge and insert all possible caller vallues for all parameter IDs contained in the given value.
    /// Absolute values are merged separately to prevent widening operations during the merge.
    ///
    /// Since recursive function calls could lead to infinite loops during the merge operation,
    /// each parameter ID is substituted at most once during the algorithm.
    /// This can lead to unresolved parameter IDs still contained in the final result,
    /// in some cases this can also happen without the presence of recursive function calls.
    pub fn recursively_substitute_param_values(&self, value: &Data) -> Data {
        let subs_list = &self.project.program.term.subs;
        let mut already_handled_ids = HashSet::new();
        let mut merged_absolute_value: Option<IntervalDomain> = value.get_absolute_value().cloned();
        let mut merged_data = value.clone();
        let mut has_stabilized = false;
        while !has_stabilized {
            has_stabilized = true;
            let mut replacement_map: BTreeMap<AbstractIdentifier, Data> = BTreeMap::new();
            for (id, offset) in merged_data.get_relative_values().clone() {
                if !already_handled_ids.insert(id.clone())
                    || !id.get_path_hints().is_empty()
                    || !subs_list.contains_key(id.get_tid())
                {
                    // ID was already present in `already_handled_ids` or it is not a parameter ID
                    replacement_map.insert(
                        id.clone(),
                        Data::from_target(id, Bitvector::zero(offset.bytesize().into()).into()),
                    );
                } else {
                    has_stabilized = false;
                    let (caller_absolute_value, caller_data) = self.substitute_param_values(&id);
                    replacement_map.insert(id, caller_data);
                    merged_absolute_value = match (
                        merged_absolute_value,
                        caller_absolute_value.map(|val| val + offset),
                    ) {
                        (Some(val_left), Some(val_right)) => {
                            Some(val_left.signed_merge(&val_right))
                        }
                        (Some(val), None) | (None, Some(val)) => Some(val.clone()),
                        (None, None) => None,
                    };
                }
            }
            merged_data.replace_all_ids(&replacement_map);
        }
        merged_data.set_absolute_value(merged_absolute_value);
        merged_data
    }

    /// Replace all parameter IDs in the given value.
    /// The replaced values are those of the parameters at the given call,
    /// i.e. the replacement is context-sensitive to a specific call.
    fn substitute_param_values_context_sensitive(
        &self,
        value: &Data,
        call_tid: &Tid,
        current_fn_tid: &Tid,
    ) -> Data {
        let mut replacement_map: BTreeMap<AbstractIdentifier, Data> = BTreeMap::new();
        for (id, offset) in value.get_relative_values().clone() {
            if id.get_tid() == current_fn_tid && id.get_path_hints().is_empty() {
                // Possible function param ID
                let param_id_at_callsite =
                    AbstractIdentifier::new(call_tid.clone(), id.get_location().clone());
                if let Some(value_at_callsite) =
                    self.param_replacement_map.get(&param_id_at_callsite)
                {
                    replacement_map.insert(id, value_at_callsite.clone());
                } // Else it is a pointer to the current stack frame, which is invalid in the caller.
            } else {
                // Not a function param.
                replacement_map.insert(
                    id.clone(),
                    Data::from_target(id, Bitvector::zero(offset.bytesize().into()).into()),
                );
            }
        }
        let mut result = value.clone();
        result.replace_all_ids(&replacement_map);
        result
    }

    /// Replace all parameter IDs in the given value using the given path hints
    /// to replace them with the corresponding values in the calling context of the path hints.
    pub fn recursively_substitute_param_values_context_sensitive(
        &self,
        value: &Data,
        current_fn_tid: &Tid,
        path_hints: &[Tid],
    ) -> Data {
        let mut substituted_value = value.clone();
        let mut current_fn_tid = current_fn_tid.clone();
        if path_hints.is_empty() {
            return substituted_value;
        }
        for call_tid in path_hints {
            substituted_value = self.substitute_param_values_context_sensitive(
                &substituted_value,
                call_tid,
                &current_fn_tid,
            );
            // Now set the new current_fn_tid to the TID of the caller function.
            current_fn_tid = self.call_to_caller_fn_map[call_tid].clone();
        }
        substituted_value
    }

    /// Log a debug log message in the log collector of `self`.
    fn log_debug(&self, tid: &Tid, msg: impl ToString) {
        let log_msg = LogMessage {
            text: msg.to_string(),
            level: crate::utils::log::LogLevel::Debug,
            location: Some(tid.clone()),
            source: Some(super::CWE_MODULE.name.to_string()),
        };
        self.log_collector.send(log_msg.into()).unwrap();
    }

    /// Check whether the given parameter at the given callsite may point outside of its corresponding memory object.
    /// If yes, then generate a CWE warning.
    fn check_param_at_call(
        &self,
        state: &mut State,
        param: &Arg,
        call_tid: &Tid,
        target_fn_name: Option<&str>,
    ) {
        if let Some(possible_address) = self
            .pointer_inference
            .eval_parameter_arg_at_call(call_tid, param)
        {
            let warnings = state.check_address_access(&possible_address, ByteSize::new(1), self);
            if !warnings.is_empty() {
                let description = match target_fn_name {
                    Some(target_name) => format!(
                        "(Buffer Overflow) Call to {} at {} may access out-of-bounds memory.",
                        target_name, &call_tid.address
                    ),
                    None => format!(
                        "(Buffer Overflow) Call at {} may access out-of-bounds memory.",
                        &call_tid.address
                    ),
                };
                let mut cwe_warning =
                    CweWarning::new("CWE119", super::CWE_MODULE.version, description);
                cwe_warning.tids = vec![format!("{}", call_tid)];
                cwe_warning.addresses = vec![call_tid.address.to_string()];
                cwe_warning.other = vec![warnings];
                self.log_collector.send(cwe_warning.into()).unwrap();
            }
        }
    }
}

/// Compute a map that maps the TIDs of functions to the set of TIDs of all known callsites to the corresponding function.
fn compute_callee_to_call_sites_map(project: &Project) -> HashMap<Tid, HashSet<Tid>> {
    let mut callee_to_call_sites_map: HashMap<Tid, HashSet<Tid>> = HashMap::new();
    for sub in project.program.term.subs.values() {
        for blk in &sub.term.blocks {
            for jmp in &blk.term.jmps {
                match &jmp.term {
                    Jmp::Call { target, .. } => {
                        let callsites = callee_to_call_sites_map.entry(target.clone()).or_default();
                        callsites.insert(jmp.tid.clone());
                    }
                    Jmp::CallInd { .. } => (), // FIXME: indirect call targets not yet supported.
                    _ => (),
                }
            }
        }
    }
    callee_to_call_sites_map
}

/// Compute a mapping that maps each parameter of each call (given by an abstract identifier representing the parameter value at the callsite).
/// to its value at the callsite according to the pointer inference analysis.
fn compute_param_replacement_map(
    analysis_results: &AnalysisResults,
) -> HashMap<AbstractIdentifier, Data> {
    let mut param_replacement_map = HashMap::new();
    for sub in analysis_results.project.program.term.subs.values() {
        for blk in &sub.term.blocks {
            for jmp in &blk.term.jmps {
                match &jmp.term {
                    Jmp::Call { target, .. } => add_param_replacements_for_call(
                        analysis_results,
                        jmp,
                        target,
                        &mut param_replacement_map,
                    ),
                    Jmp::CallInd { .. } => (), // FIXME: indirect call targets not yet supported.
                    _ => (),
                }
            }
        }
    }
    param_replacement_map
}

/// For each parameter of the given call term map the abstract identifier representing the value of the parameter at the callsite
/// to its concrete value (in the context of the caller).
/// Add the mappings to the given `replacement_map`.
fn add_param_replacements_for_call(
    analysis_results: &AnalysisResults,
    call: &Term<Jmp>,
    callee_tid: &Tid,
    replacement_map: &mut HashMap<AbstractIdentifier, Data>,
) {
    let vsa_results = analysis_results.pointer_inference.unwrap();
    if let Some(fn_sig) = analysis_results
        .function_signatures
        .unwrap()
        .get(callee_tid)
    {
        for param_arg in fn_sig.parameters.keys() {
            if let Some(param_value) = vsa_results.eval_parameter_arg_at_call(&call.tid, param_arg)
            {
                let param_id = AbstractIdentifier::from_arg(&call.tid, param_arg);
                replacement_map.insert(param_id, param_value);
            }
        }
    } else if let Some(extern_symbol) = analysis_results
        .project
        .program
        .term
        .extern_symbols
        .get(callee_tid)
    {
        for param_arg in &extern_symbol.parameters {
            if let Some(param_value) = vsa_results.eval_parameter_arg_at_call(&call.tid, param_arg)
            {
                let param_id = AbstractIdentifier::from_arg(&call.tid, param_arg);
                replacement_map.insert(param_id, param_value);
            }
        }
    }
}

/// Compute a map mapping the TIDs of malloc-like calls (e.g. malloc, realloc, calloc)
/// to the size value of the allocated object according to the pointer inference analysis.
fn compute_size_values_of_malloc_calls(analysis_results: &AnalysisResults) -> HashMap<Tid, Data> {
    let project = analysis_results.project;
    let pointer_inference = analysis_results.pointer_inference.unwrap();
    let mut malloc_size_map = HashMap::new();
    for sub in analysis_results.project.program.term.subs.values() {
        for blk in &sub.term.blocks {
            for jmp in &blk.term.jmps {
                if let Jmp::Call { target, .. } = &jmp.term {
                    if let Some(symbol) = project.program.term.extern_symbols.get(target) {
                        if let Some(size_value) = compute_size_value_of_malloc_like_call(
                            &jmp.tid,
                            symbol,
                            pointer_inference,
                        ) {
                            malloc_size_map.insert(jmp.tid.clone(), size_value);
                        }
                    }
                }
            }
        }
    }
    malloc_size_map
}

/// Compute the size value of a call to a malloc-like function according to the pointer inference and return it.
/// Returns `None` if the called symbol is not an allocating function or the size computation for the symbol is not yet implemented.
///
/// Currently this function computes the size values for the symbols `malloc`, `realloc` and `calloc`.
fn compute_size_value_of_malloc_like_call(
    jmp_tid: &Tid,
    called_symbol: &ExternSymbol,
    pointer_inference: &PointerInference,
) -> Option<Data> {
    match called_symbol.name.as_str() {
        "malloc" => {
            let size_param = &called_symbol.parameters[0];
            match pointer_inference.eval_parameter_arg_at_call(jmp_tid, size_param) {
                Some(size_value) => Some(size_value),
                None => Some(Data::new_top(size_param.bytesize())),
            }
        }
        "realloc" => {
            let size_param = &called_symbol.parameters[1];
            match pointer_inference.eval_parameter_arg_at_call(jmp_tid, size_param) {
                Some(size_value) => Some(size_value),
                None => Some(Data::new_top(size_param.bytesize())),
            }
        }
        "calloc" => {
            let count_param = &called_symbol.parameters[0];
            let size_param = &called_symbol.parameters[1];
            match (
                pointer_inference.eval_parameter_arg_at_call(jmp_tid, count_param),
                pointer_inference.eval_parameter_arg_at_call(jmp_tid, size_param),
            ) {
                (Some(count_value), Some(size_value)) => {
                    Some(count_value.bin_op(BinOpType::IntMult, &size_value))
                }
                _ => Some(Data::new_top(size_param.bytesize())),
            }
        }
        _ => None,
    }
}

/// Compute a map that maps the TIDs of call instructions to the TID of the caller function.
fn compute_call_to_caller_map(project: &Project) -> HashMap<Tid, Tid> {
    let mut call_to_caller_map = HashMap::new();
    for (sub_tid, sub) in &project.program.term.subs {
        for block in &sub.term.blocks {
            for jmp in &block.term.jmps {
                match &jmp.term {
                    Jmp::Call { .. } | Jmp::CallInd { .. } | Jmp::CallOther { .. } => {
                        call_to_caller_map.insert(jmp.tid.clone(), sub_tid.clone());
                    }
                    _ => (),
                }
            }
        }
    }
    call_to_caller_map
}

#[cfg(test)]
pub mod tests;
