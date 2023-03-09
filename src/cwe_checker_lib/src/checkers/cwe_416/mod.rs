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

use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::utils::log::LogThread;
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
    let log_thread = LogThread::spawn(LogThread::collect_and_deduplicate);
    let context = Context::new(analysis_results, log_thread.get_msg_sender());

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
    let (logs, cwe_warnings) = log_thread.collect();
    (logs, cwe_warnings)
}
