use crate::abstract_domain::*;
use crate::analysis::callgraph::CallGraph;
use crate::analysis::function_signature::FunctionSignature;
use crate::analysis::graph::Graph;
use crate::analysis::pointer_inference::{Data, PointerInference};
use crate::intermediate_representation::*;
use crate::utils::log::{CweWarning, LogMessage, LogThreadMsg};
use crate::{analysis::vsa_results::VsaResult, prelude::*};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::state::State;

/// Methods of [`Context`] related to computing bounds of memory objects.
mod bounds_computation;
pub use bounds_computation::BoundsMetadata;
/// Methods of [`Context`] and other helper functions related to replacing parameter IDs with possible caller values.
mod param_replacement;
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
    /// The callgraph corresponding to the project.
    pub callgraph: CallGraph<'a>,
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
        let callgraph = crate::analysis::callgraph::get_program_callgraph(&project.program);
        Context {
            project,
            graph: analysis_results.control_flow_graph,
            pointer_inference: analysis_results.pointer_inference.unwrap(),
            function_signatures: analysis_results.function_signatures.unwrap(),
            callee_to_callsites_map: compute_callee_to_call_sites_map(project),
            param_replacement_map: param_replacement::compute_param_replacement_map(
                analysis_results,
            ),
            malloc_tid_to_object_size_map: compute_size_values_of_malloc_calls(analysis_results),
            call_to_caller_fn_map: compute_call_to_caller_map(project),
            callgraph,
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
                        let (lower_bound, upper_bound) = (
                            Bitvector::from_i64(lower_bound)
                                .into_resize_signed(object_size.bytesize()),
                            Bitvector::from_i64(upper_bound)
                                .into_resize_signed(object_size.bytesize()),
                        );
                        if lower_bound.is_zero() || upper_bound.is_zero() {
                            self.log_info(object_id.get_tid(), "Heap object may have size zero. This may indicate an instance of CWE-687.");
                        }
                        if upper_bound.sign_bit().to_bool() || upper_bound.is_zero() {
                            // Both bounds seem to be bogus values (because both are non-positive values).
                            BitvectorDomain::new_top(object_size.bytesize())
                        } else if lower_bound.sign_bit().to_bool() || lower_bound.is_zero() {
                            // The lower bound is bogus, but we can approximate by the upper bound instead.
                            upper_bound.into()
                        } else {
                            // We approximate the object size with the smallest possible value.
                            lower_bound.into()
                        }
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

    /// Log a debug log message in the log collector of `self`.
    pub fn log_debug(&self, tid: &Tid, msg: impl ToString) {
        let log_msg = LogMessage {
            text: msg.to_string(),
            level: crate::utils::log::LogLevel::Debug,
            location: Some(tid.clone()),
            source: Some(super::CWE_MODULE.name.to_string()),
        };
        self.log_collector.send(log_msg.into()).unwrap();
    }

    /// Log an info log message in the log collector of `self`.
    pub fn log_info(&self, tid: &Tid, msg: impl ToString) {
        let log_msg = LogMessage {
            text: msg.to_string(),
            level: crate::utils::log::LogLevel::Info,
            location: Some(tid.clone()),
            source: Some(super::CWE_MODULE.name.to_string()),
        };
        self.log_collector.send(log_msg.into()).unwrap();
    }

    /// Check whether the given parameter at the given callsite may point outside of its corresponding memory object.
    /// If yes, then generate a CWE warning.
    pub fn check_param_at_call(
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
                cwe_warning.tids = vec![format!("{call_tid}")];
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
