//! This module implements a check for CWE-415: Double Free and CWE-416: Use After Free.
//!
//! If a program tries to reference memory objects or other resources after they have been freed
//! it can lead to crashes, unexpected behaviour or even arbitrary code execution.
//! The same is true if the program tries to free the same resource more than once
//! as this can lead to another unrelated resource being freed instead.
//!
//! See <https://cwe.mitre.org/data/definitions/415.html> and <https://cwe.mitre.org/data/definitions/416.html> for detailed descriptions.
//!
//! ## How the check works
//!
//! Using an interprocedural, bottom-up dataflow analysis
//! based on the results of the [Pointer Inference analysis](`crate::analysis::pointer_inference`)
//! the check keeps track of memory objects that have already been freed.
//! If a pointer to an already freed object is used to access memory or provided as a parameter to another function
//! then a CWE warning is generated.
//! To prevent duplicate CWE warnings with the same root cause
//! the check also keeps track of objects for which a CWE warning was already generated.
//!
//! ## False Positives
//!
//! - Since the analysis is not path-sensitive, infeasible paths may lead to false positives.
//! - Any analysis imprecision of the pointer inference analysis
//! that leads to assuming that a pointer can target more memory objects that it actually can target
//! may lead to false positive CWE warnings in this check.
//!
//! ## False Negatives
//!
//! - Arrays of memory objects are not tracked by this analysis as we currently cannot distinguish different array elements in the analysis.
//! Subsequently, CWEs corresponding to arrays of memory objects are not detected.
//! - Memory objects not tracked by the Pointer Inference analysis or pointer targets missed by the Pointer Inference
//! may lead to missed CWEs in this check.
//! - The analysis currently only tracks pointers to objects that were freed by a call to `free`.
//! If a memory object is freed by another external function then this may lead to false negatives in this check.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::AbstractIdentifier;
use crate::analysis::fixpoint::Computation;
use crate::analysis::forward_interprocedural_fixpoint::GeneralizedContext;
use crate::analysis::graph::Node;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::CweModule;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE416",
    version: "0.3",
    run: check_cwe,
};

mod context;
use context::Context;
mod state;
use state::State;

/// Run the check for CWE-416: Use After Free.
///
/// This function prepares the bottom-up fixpoint computation
/// by initializing the state at the start of each function with the empty state (i.e. no dangling objects known)
/// and then executing the fixpoint algorithm.
/// Returns collected log messages and CWE warnings.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    _config: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let (cwe_warning_sender, cwe_warning_receiver) = crossbeam_channel::unbounded();
    let (log_sender, log_receiver) = crossbeam_channel::unbounded();
    let context = Context::new(analysis_results, cwe_warning_sender, log_sender);

    let mut fixpoint_computation =
        crate::analysis::forward_interprocedural_fixpoint::create_computation(context, None);

    for (sub_tid, entry_node_of_sub) in
        crate::analysis::graph::get_entry_nodes_of_subs(analysis_results.control_flow_graph)
    {
        let fn_start_state = State::new(sub_tid);
        fixpoint_computation.set_node_value(
            entry_node_of_sub,
            crate::analysis::interprocedural_fixpoint_generic::NodeValue::Value(fn_start_state),
        );
    }

    fixpoint_computation.compute_with_max_steps(100);

    let mut warnings = HashSet::new();
    while let Ok(warning) = cwe_warning_receiver.try_recv() {
        warnings.insert(warning);
    }
    let return_site_states = collect_return_site_states(&fixpoint_computation);
    let cwes = generate_context_information_for_warnings(return_site_states, warnings);

    let mut logs = BTreeSet::new();
    while let Ok(log_msg) = log_receiver.try_recv() {
        logs.insert(log_msg);
    }

    (logs.into_iter().collect(), cwes.into_iter().collect())
}

/// A struct for collecting CWE warnings together with context information
/// that can be used to post-process the warning after the fixpoint has been computed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WarningContext {
    /// The CWE warning.
    cwe: CweWarning,
    /// The TID of the function in which the CWE warning was generated.
    root_function: Tid,
    /// Pairs of object IDs and the sites where the object was freed.
    /// If the free-site is the same function call from which the object ID originates
    /// then the CWE needs to be post-processed to give more exact information about the
    /// free-site inside the function call.
    object_and_free_ids: Vec<(AbstractIdentifier, Tid)>,
}

impl WarningContext {
    /// Generate a new warning context object.
    pub fn new(
        cwe: CweWarning,
        object_and_free_ids: Vec<(AbstractIdentifier, Tid)>,
        root_function: Tid,
    ) -> Self {
        WarningContext {
            cwe,
            root_function,
            object_and_free_ids,
        }
    }
}

/// For each function call TID collect the state of the callee just before returning to the caller.
fn collect_return_site_states<'a>(
    fixpoint: &Computation<GeneralizedContext<'a, Context<'a>>>,
) -> HashMap<Tid, State> {
    let mut call_tid_to_return_state_map: HashMap<Tid, State> = HashMap::new();
    let graph = fixpoint.get_graph();
    for node in graph.node_indices() {
        let call_tid = match graph[node] {
            Node::CallReturn { call, return_: _ } => call.0.term.jmps[0].tid.clone(),
            _ => continue,
        };
        let node_value = match fixpoint.get_node_value(node) {
            Some(value) => value,
            None => continue,
        };
        let return_state = match node_value {
            NodeValue::CallFlowCombinator {
                call_stub: _,
                interprocedural_flow,
            } => {
                if let Some(state) = interprocedural_flow {
                    state.clone()
                } else {
                    continue;
                }
            }
            _ => panic!("Unexpexted NodeValue type encountered."),
        };
        // There exists one CallReturn node for each return instruction in the callee,
        // so we have to merge the corresponding states here.
        call_tid_to_return_state_map
            .entry(call_tid)
            .and_modify(|saved_return_state| {
                *saved_return_state = saved_return_state.merge(&return_state)
            })
            .or_insert(return_state);
    }
    call_tid_to_return_state_map
}

/// If the ID of the "free"-site is the same call from which the object ID originates from
/// then (recursively) identify the real "free"-site inside the call.
/// Also return a list of call TIDs that lead to the real "free"-site.
///
/// The function returns an error if the source object was already flagged in some of the callees.
/// In such a case the corresponding CWE warning should be removed,
/// since there already exists another CWE warning with the same root cause.
fn get_source_of_free(
    object_id: &AbstractIdentifier,
    free_id: &Tid,
    return_site_states: &HashMap<Tid, State>,
) -> Result<(Tid, Vec<Tid>), ()> {
    if let (inner_object, Some(path_hint_id)) = object_id.without_last_path_hint() {
        if path_hint_id == *free_id {
            if let Some(return_state) = return_site_states.get(free_id) {
                if return_state.is_id_already_flagged(&inner_object) {
                    return Err(());
                }
                if let Some(inner_free) = return_state.get_free_tid_if_dangling(&inner_object) {
                    let (root_free, mut callgraph_ids) =
                        get_source_of_free(&inner_object, inner_free, return_site_states)?;
                    callgraph_ids.push(path_hint_id);
                    return Ok((root_free, callgraph_ids));
                }
            }
        }
    }
    // No inner source apart from the given free_id could be identified
    Ok((free_id.clone(), Vec::new()))
}

/// Generate context information for CWE warnings.
/// E.g. relevant callgraph addresses are added to each CWE here.
fn generate_context_information_for_warnings(
    return_site_states: HashMap<Tid, State>,
    warnings: HashSet<WarningContext>,
) -> BTreeSet<CweWarning> {
    let mut processed_warnings = BTreeSet::new();
    for mut warning in warnings {
        let mut context_infos = Vec::new();
        let mut relevant_callgraph_tids = Vec::new();
        for (object_id, free_id) in warning.object_and_free_ids.iter() {
            if let Ok((root_free_id, mut callgraph_ids_to_free)) =
                get_source_of_free(object_id, free_id, &return_site_states)
            {
                relevant_callgraph_tids.append(&mut callgraph_ids_to_free);
                context_infos.push(format!(
                    "Accessed ID {object_id} may have been freed before at {root_free_id}."
                ));
            }
        }
        if context_infos.is_empty() {
            // Skip (delete) this CWE warning,
            // since another warning with the same root cause was already generated in some callee.
            continue;
        }
        let mut callgraph_tids_as_string = format!("{}", warning.root_function);
        for id in relevant_callgraph_tids {
            callgraph_tids_as_string += &format!(", {id}");
        }
        context_infos.push(format!(
            "Relevant callgraph TIDs: [{callgraph_tids_as_string}]"
        ));
        warning.cwe.other = vec![context_infos];
        processed_warnings.insert(warning.cwe);
    }

    processed_warnings
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        abstract_domain::{AbstractIdentifier, AbstractLocation},
        checkers::cwe_416::WarningContext,
        intermediate_representation::*,
        utils::log::CweWarning,
        variable,
    };

    #[test]
    fn test_warning_context_generation() {
        let id = AbstractIdentifier::new(
            Tid::new("object_origin_tid"),
            AbstractLocation::Register(variable!("RAX:8")),
        );
        let path_id = id.with_path_hint(Tid::new("call_tid")).unwrap();
        let object_and_free_ids = vec![(path_id, Tid::new("call_tid"))];

        let cwe = CweWarning::new("CWE416", "test", "mock_cwe");
        let warning_context =
            WarningContext::new(cwe, object_and_free_ids, Tid::new("root_func_tid"));
        let warnings = HashSet::from([warning_context]);

        // Test warning context generation
        let return_state = State::mock(
            Tid::new("callee_tid"),
            &[(id.clone(), Tid::new("free_tid"))],
            &[],
        );
        let return_site_states = HashMap::from([(Tid::new("call_tid"), return_state)]);
        let processed_warnings =
            generate_context_information_for_warnings(return_site_states, warnings.clone());
        assert_eq!(processed_warnings.len(), 1);
        let processed_cwe = processed_warnings.iter().next().unwrap();
        assert_eq!(&processed_cwe.other[0], &[
            "Accessed ID object_origin_tid(->call_tid) @ RAX may have been freed before at free_tid.".to_string(),
            "Relevant callgraph TIDs: [root_func_tid, call_tid]".to_string(),
        ]);

        // Test warning filtering
        let return_state = State::mock(Tid::new("callee_tid"), &[], &[id.clone()]);
        let return_site_states = HashMap::from([(Tid::new("call_tid"), return_state)]);
        let processed_warnings =
            generate_context_information_for_warnings(return_site_states, warnings);
        assert_eq!(processed_warnings.len(), 0)
    }
}
