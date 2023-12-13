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
//! ### Symbols configurable in config.json
//!
//! - The `deallocation_symbols` are the names of extern functions that deallocate memory.
//! The check always assumes that the first parameter of such a function is the memory object to be freed.
//! The check also assumes that memory is always freed by such a call,
//! which can lead to false positive warnings for functions like `realloc`, where the memory object may not be freed by the call.
//! - The `always_include_full_path_to_free_site` flag controls the amount of context information printed in the CWE warnings.
//! If set to `true`, then the warning contains the full path in the callgraph from the root function to an actual `free`-site.
//! If set to `false`, then the path may be shortened:
//! A call to some function `func` may be reported as the `free`-site
//! if the actual `free`-operation is contained in `func` or some callee of `func`.
//!
//! ## False Positives
//!
//! - Since the analysis is not path-sensitive, infeasible paths may lead to false positives.
//! - Any analysis imprecision of the pointer inference analysis
//! that leads to assuming that a pointer can target more memory objects that it actually can target
//! may lead to false positive CWE warnings in this check.
//! - For extern functions that may or may not release memory,
//! the check will produce false positives if the original pointer is used after calling the function.
//! For example, `realloc` may return NULL, in which case it will not free memory and the original pointer remains valid.
//! But the check will flag any access to the original pointer as a potential CWE, regardless of the return value of `realloc`.
//!
//! ## False Negatives
//!
//! - Arrays of memory objects are not tracked by this analysis as we currently cannot distinguish different array elements in the analysis.
//! Subsequently, CWEs corresponding to arrays of memory objects are not detected.
//! - Memory objects not tracked by the Pointer Inference analysis or pointer targets missed by the Pointer Inference
//! may lead to missed CWEs in this check.
//! - Pointers freed by other operations than calls to the deallocation symbols contained in the config.json will be missed by the analysis.
//! - Pointers freed and flagged in the same call are not marked as freed in the caller.
//! This reduces false positives and duplicates, but may also result in some false negatives.
//! - Objects freed in the same call where they are created are not marked as freed in the caller.
//! This reduces false positives, but may also result in some false negatives.

use crate::abstract_domain::AbstractIdentifier;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::CweModule;
use std::collections::BTreeSet;
use std::collections::HashSet;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE416",
    version: "0.3",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// The names of symbols that free memory (e.g. the "free" function of C).
    /// The analysis always assumes that the memory object to be freed is the first parameter of the function.
    deallocation_symbols: Vec<String>,
    /// If this flag is set to `true`,
    /// then always include the full path to the actual `free`-site in the callgraph in the CWE warning context information.
    always_include_full_path_to_free_site: bool,
}

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
    config_json: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(config_json.clone()).unwrap();
    let deallocation_symbols = config.deallocation_symbols.iter().cloned().collect();
    let (cwe_warning_sender, cwe_warning_receiver) = crossbeam_channel::unbounded();
    let (log_sender, log_receiver) = crossbeam_channel::unbounded();
    let context = Context::new(
        analysis_results,
        cwe_warning_sender,
        log_sender,
        deallocation_symbols,
    );

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

    let mut warnings = BTreeSet::new();
    while let Ok(warning) = cwe_warning_receiver.try_recv() {
        warnings.insert(warning);
    }
    let cwes = generate_context_information_for_warnings(
        warnings,
        config.always_include_full_path_to_free_site,
    );

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
    /// Pairs of object IDs and the paths to the actual free sites.
    object_and_free_ids: Vec<(AbstractIdentifier, Vec<Tid>)>,
}

impl WarningContext {
    /// Generate a new warning context object.
    pub fn new(
        cwe: CweWarning,
        object_and_free_ids: Vec<(AbstractIdentifier, Vec<Tid>)>,
        root_function: Tid,
    ) -> Self {
        WarningContext {
            cwe,
            root_function,
            object_and_free_ids,
        }
    }
}

/// Shorten the path to the "free"-site so that it ends in the first call
/// that is not contained in the path to the object origin.
fn get_shortended_path_to_source_of_free(
    object_id: &AbstractIdentifier,
    free_path: &[Tid],
) -> Vec<Tid> {
    let mut object_id = object_id.clone();
    let mut shortened_free_path = free_path.to_vec();
    while let (shortened_id, Some(last_path_hint)) = object_id.without_last_path_hint() {
        if Some(&last_path_hint) == shortened_free_path.last() {
            object_id = shortened_id;
            shortened_free_path.pop();
        } else {
            break;
        }
    }
    // Return the free path without the shortened free path
    if shortened_free_path.is_empty() {
        free_path.to_vec()
    } else {
        free_path[(shortened_free_path.len() - 1)..].to_vec()
    }
}

/// Get the part of the path to the "free"-site that is not shared with the path to the object origin site.
fn get_root_cause_for_returned_dangling_pointers(
    object_id: &AbstractIdentifier,
    free_path: &[Tid],
) -> Vec<Tid> {
    let mut object_id = object_id.clone();
    let mut shortened_free_path = free_path.to_vec();
    while let (shortened_id, Some(last_path_hint)) = object_id.without_last_path_hint() {
        if Some(&last_path_hint) == shortened_free_path.last() {
            object_id = shortened_id;
            shortened_free_path.pop();
        } else {
            break;
        }
    }
    if shortened_free_path.is_empty() {
        vec![free_path[0].clone()]
    } else {
        shortened_free_path
    }
}

/// Return `true` if the object originates in the same call as the "free"-site.
fn is_case_of_returned_dangling_pointer(object_id: &AbstractIdentifier, free_path: &[Tid]) -> bool {
    // This implicitly uses that the `free_path` is never empty.
    object_id.get_path_hints().last() == free_path.last()
}

/// Generate context information for CWE warnings.
/// E.g. relevant callgraph addresses are added to each CWE here.
fn generate_context_information_for_warnings(
    warnings: BTreeSet<WarningContext>,
    generate_full_paths_to_free_site: bool,
) -> BTreeSet<CweWarning> {
    let mut processed_warnings = BTreeSet::new();
    let mut root_causes_for_returned_dangling_pointers = HashSet::new();

    for mut warning in warnings {
        let mut context_infos = Vec::new();
        let mut relevant_callgraph_tids = BTreeSet::new();
        for (object_id, mut free_path) in warning.object_and_free_ids.into_iter() {
            if is_case_of_returned_dangling_pointer(&object_id, &free_path) {
                let root_cause =
                    get_root_cause_for_returned_dangling_pointers(&object_id, &free_path);
                if root_causes_for_returned_dangling_pointers.contains(&root_cause) {
                    // Skip this warning root cause, since another warning with the same root cause was already generated.
                    // FIXME: This is a coarse heuristic to reduce false positives.
                    // However, it is still possible that some but not all of these cases are real bugs
                    // and that this heuristic chooses the wrong representative.
                    continue;
                } else {
                    root_causes_for_returned_dangling_pointers.insert(root_cause);
                }
            }
            if !generate_full_paths_to_free_site {
                free_path = get_shortended_path_to_source_of_free(&object_id, &free_path);
            }
            for id in &free_path[1..] {
                relevant_callgraph_tids.insert(id.clone());
            }
            context_infos.push(format!(
                "Accessed ID {object_id} may have been freed before at {}.",
                free_path[0]
            ));
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
        let object_id = id.with_path_hint(Tid::new("call_tid")).unwrap();
        let object_and_free_ids = vec![(
            object_id.clone(),
            vec![Tid::new("free_tid"), Tid::new("call_tid")],
        )];

        let cwe = CweWarning::new("CWE416", "test", "mock_cwe");
        let warning_context =
            WarningContext::new(cwe, object_and_free_ids, Tid::new("root_func_tid"));
        let warnings = BTreeSet::from([warning_context.clone()]);

        // Test warning context generation
        let processed_warnings = generate_context_information_for_warnings(warnings.clone(), false);
        assert_eq!(processed_warnings.len(), 1);
        let processed_cwe = processed_warnings.iter().next().unwrap();
        assert_eq!(&processed_cwe.other[0], &[
            "Accessed ID object_origin_tid(->call_tid) @ RAX:i64 may have been freed before at free_tid.".to_string(),
            "Relevant callgraph TIDs: [root_func_tid, call_tid]".to_string(),
        ]);

        // Test warning filtering
        let object_and_free_ids_2 = vec![(
            object_id
                .with_path_hint(Tid::new("outer_call_tid"))
                .unwrap(),
            vec![
                Tid::new("free_tid"),
                Tid::new("call_tid"),
                Tid::new("outer_call_tid"),
            ],
        )];
        let cwe_2 = CweWarning::new("CWE416", "test", "mock_cwe_2");
        let warning_context_2 =
            WarningContext::new(cwe_2, object_and_free_ids_2, Tid::new("root_func_tid_2"));
        let warnings = BTreeSet::from([warning_context, warning_context_2]);
        let processed_warnings = generate_context_information_for_warnings(warnings, false);
        assert_eq!(processed_warnings.len(), 1)
    }
}
