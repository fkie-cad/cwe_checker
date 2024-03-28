//! CWE-252: Unchecked Return Value.
//!
//! It is a common programming pattern that called procedures indicate their
//! success or failure to the caller via their return value. If a caller does
//! not check the return value of a called procedure they can not know if the
//! operation was successful or not. This may lead to bugs with security
//! implications when the program resumes execution under the assumption that
//! the failed call has worked.
//!
//! # Examples
//!
//! See CVE for examples in Linux user-mode programs:
//!
//! - CVE-2007-5191
//! - CVE-2017-6964
//! - CVE-2018-16643
//! - CVE-2019-15900
//! - CVE-2023-40303
//!
//! Also see [CWE252 at Mitre].
//!
//! [CWE252 at Mitre]: https://cwe.mitre.org/data/definitions/252.html
//!
//! # Algorithm
//!
//! We perform a taint analysis where the sources are return values of calls to
//! external functions and the sinks are:
//!
//! - Places where all taint vanishes from the state. Here, the program losses
//!   all information about success of failure of the API call; thus, it can not
//!   possibly adapt its behavior in the subsequent execution.
//! - Taint reaches a return site of a function without any taint being returned
//!   to the caller. Here, the caller of the function cannot know if the API
//!   call was successful.
//!
//! Taint propagation is stopped along paths as soon as a conditional control
//! flow transfer depend on a tainted value.
//!
//! # Limitations
//!
//! ## False Positives
//!
//! - For many API functions the necessity to check the return value depends on
//!   the context of the caller.
//! - Cases where the result is checked before it is assumed that the operation
//!   has worked, but there are paths from the call site that are correct
//!   irrespective of the success or failure of the call.
//! - Patterns where the return value is handled by giving it as an argument to
//!   another function call.
//! - ...
//!
//! ## False Negatives
//!
//! - Return value is checked but the program does not act accordingly.
//! - The API function is not in the list of checked functions.
//!
//! # Configuration
//!
//! The list of checked external functions can be configured via the
//! `config.json`. By selecting the `strict_mode` additional functions can be
//! included, however, those are more likely to produce false positives.

use crate::analysis::graph::{Edge, NodeIndex};
use crate::analysis::pointer_inference::PointerInference;
use crate::intermediate_representation::{ExternSymbol, Jmp, Project, Term};
use crate::pipeline::AnalysisResults;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils;
use crate::CweModule;

use petgraph::visit::EdgeRef;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;

mod context;
mod isolated_returns;

use context::*;
use isolated_returns::*;

/// CWE-252: Unchecked Return Value.
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE252",
    version: "0.1",
    run: check_cwe,
};

/// Configuration of the check; this is read from the `config.json` file.
#[derive(Deserialize)]
struct Config {
    strict_mode: bool,
    /// External symbols whose return values must be checked.
    symbols: HashSet<String>,
    /// Additional symbols that are only checked when we run in strict mode.
    strict_symbols: HashSet<String>,
}

impl Config {
    fn into_symbols(mut self) -> HashSet<String> {
        if self.strict_mode {
            self.symbols.extend(self.strict_symbols);
        }

        self.symbols
    }
}

/// Call whose return value must be checked.
#[derive(Clone, Copy)]
struct MustUseCall<'a> {
    /// Information about the function that was called.
    symbol: &'a ExternSymbol,
    /// CFG node where the call will return to.
    return_node: NodeIndex,
    /// IR instruction of the call.
    jmp: &'a Term<Jmp>,
}

impl MustUseCall<'_> {
    /// Returns a copy of the name of the external function that was called.
    pub fn get_symbol_name(&self) -> String {
        self.symbol.name.clone()
    }
}

/// List of calls to analyze.
struct Worklist<'a> {
    /// Remaining calls to analyze.
    calls: VecDeque<MustUseCall<'a>>,
}

impl<'a> Worklist<'a> {
    /// Creates a new worklist of external function calls to analyze.
    ///
    /// Searches the program for calls to the functions specified in the
    /// `config` and gathers them into a new worklist.
    fn new(analysis_results: &'a AnalysisResults, symbols: &HashSet<String>) -> Self {
        let symbol_map = symbol_utils::get_symbol_map_fast(analysis_results.project, symbols);
        let cfg = analysis_results
            .pointer_inference
            .expect("CWE252: BUG: No pointer inference results.")
            .get_graph();

        Worklist {
            calls: cfg
                .edge_references()
                .filter_map(|edge| {
                    let Edge::ExternCallStub(jmp) = edge.weight() else {
                        return None;
                    };
                    let Jmp::Call { target, .. } = &jmp.term else {
                        return None;
                    };
                    let return_node = edge.target();
                    Some(MustUseCall {
                        symbol: symbol_map.get(target)?,
                        return_node,
                        jmp,
                    })
                })
                .collect(),
        }
    }
}

/// Represents the full CWE252 analysis of a given project.
struct CweAnalysis<'a, 'b: 'a> {
    /// Remaining calls to external functions that need to be analyzed.
    worklist: Worklist<'a>,
    isolated_returns: Arc<IsolatedReturns<'a>>,
    project: &'a Project,
    pi_result: &'a PointerInference<'b>,
    /// Used to collect CWE warnings sent by the analyses for inidividual calls.
    cwe_collector: crossbeam_channel::Receiver<CweWarning>,
    /// Given to analyses for inidividual calls to send their CWE warnings.
    cwe_sender_proto: crossbeam_channel::Sender<CweWarning>,
}

impl<'a, 'b: 'a> CweAnalysis<'a, 'b> {
    /// Creates a new CWE252 analysis for the given project and configuration.
    fn new(analysis_results: &'a AnalysisResults<'b>, config: Config) -> Self {
        let channel = crossbeam_channel::unbounded();
        let cfg = analysis_results.control_flow_graph;

        Self {
            worklist: Worklist::new(analysis_results, &config.into_symbols()),
            isolated_returns: Arc::new(get_isolated_returns(cfg)),
            project: analysis_results.project,
            pi_result: analysis_results.pointer_inference.unwrap(),
            cwe_collector: channel.1,
            cwe_sender_proto: channel.0,
        }
    }

    /// Pops a call of the worklist and returns the taint analysis definition
    /// for it.
    fn next_call_ctx(&mut self) -> Option<(IsolatedReturnAnalysis<'_>, TaCompCtx<'_, 'b>)> {
        self.worklist.calls.pop_front().map(|call| {
            (
                IsolatedReturnAnalysis::new(
                    call,
                    Arc::clone(&self.isolated_returns),
                    self.project,
                    self.cwe_sender_proto.clone(),
                ),
                TaCompCtx::new(call, self.project, self.pi_result, &self.cwe_sender_proto),
            )
        })
    }

    /// Runs the CWE252 analysis and returns the generated warnings.
    fn run(mut self) -> (Vec<LogMessage>, Vec<CweWarning>) {
        while let Some((isolated_returns, ta_comp_ctx)) = self.next_call_ctx() {
            let mut ta_comp = ta_comp_ctx.into_computation();

            ta_comp.compute_with_max_steps(100);

            isolated_returns.analyze(&ta_comp);
        }

        (
            Vec::new(),
            self.cwe_collector
                .try_iter()
                // FIXME: It would be nice to preerve all reasons during
                // deduplication.
                .map(|msg| (msg.tids.clone(), msg))
                .collect::<BTreeMap<_, _>>()
                .into_values()
                .collect(),
        )
    }
}

fn generate_cwe_warning(
    sender: &crossbeam_channel::Sender<CweWarning>,
    call: &MustUseCall<'_>,
    warning_location: &Tid,
    reason: &str,
) {
    let taint_source = call.jmp;
    let taint_source_name = call.get_symbol_name();
    let cwe_warning = CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Unchecked Return Value) There is no check of the return value of {} ({}).",
            taint_source.tid.address, taint_source_name
        ),
    )
    .addresses(vec![
        taint_source.tid.address.clone(),
        warning_location.address.clone(),
    ])
    .tids(vec![
        format!("{}", taint_source.tid),
        format!("{}", warning_location),
    ])
    .symbols(vec![taint_source_name])
    .other(vec![vec![format!("reason={}", reason.to_string())]]);
    sender
        .send(cwe_warning)
        .expect("CWE252: failed to send CWE warning");
}

/// CWE-252: Unchecked Return Value.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config =
        serde_json::from_value(cwe_params.clone()).expect("CWE252: invalid configuration");

    CweAnalysis::new(analysis_results, config).run()
}
