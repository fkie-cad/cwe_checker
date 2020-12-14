//! This module implements a check for CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition.
//!
//! Time-of-check Time-of-use race conditions happen when a property of a resource
//! (e.g. access rights of a file) get checked before the resource is accessed, leaving
//! a short time window for an attacker to change the entity and thus invalidating
//! the check before the access.
//!
//! See <https://cwe.mitre.org/data/definitions/367.html> for a detailed description.
//!
//! ## How the check works
//!
//! For pairs of (check-call, use-call), configurable in config.json, we check whether
//! a function may call the check-call before the use-call.
//!
//! ## False Positives
//!
//! - The check-call and the use-call may access different, unrelated resources
//! (e. g. different files).
//!
//! ## False Negatives
//!
//! - If the check-call and the use-call happen in different functions it will not
//!   be found by the check.

use crate::analysis::graph::{Edge, Graph, Node};
use crate::intermediate_representation::Jmp;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::CweModule;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};

pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE367",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct contains pairs of the form `(source_symbol, sink_symbol)`.
/// The `source_symbol` corresponds to a check-call and the `sink_symbol` corresponds to a use-call.
/// An execution path from a source call to a sink call corresponds to a possible Time-of-check Time-of-use Race Condition.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct Config {
    pairs: Vec<(String, String)>,
}

/// Check whether a call to the `sink_symbol` is reachable from the `source_node`
/// through a path of intraprocedural edges in the control flow graph.
///
/// A simple depth-first-search on the graph is used to find such a path.
fn is_reachable(
    graph: &Graph,
    source_node: NodeIndex,
    source_symbol: &Tid,
    sink_symbol: &Tid,
) -> Option<(Tid, Tid)> {
    let mut visited_nodes = HashSet::new();
    visited_nodes.insert(source_node);
    let mut worklist = vec![source_node];

    while let Some(node) = worklist.pop() {
        for edge in graph.edges(node) {
            if let Edge::ExternCallStub(jmp) = edge.weight() {
                if let Jmp::Call { target, .. } = &jmp.term {
                    if target == sink_symbol {
                        // We found a CWE hit
                        let source_tid = graph[source_node].get_block().tid.clone();
                        return Some((source_tid, jmp.tid.clone()));
                    } else if target == source_symbol {
                        // Do not search past another source call,
                        // since subsequent sink calls probably belong to the new source.
                        continue;
                    }
                }
            }
            // Add the target node to the worklist if it was not already visited
            // and as long as the edge does not leave the function.
            match edge.weight() {
                Edge::Block
                | Edge::CRCallStub
                | Edge::CRCombine(_)
                | Edge::Jump(_, _)
                | Edge::ExternCallStub(_) => {
                    if visited_nodes.get(&edge.target()).is_none() {
                        visited_nodes.insert(edge.target());
                        worklist.push(edge.target())
                    }
                }
                Edge::Call(_) | Edge::CRReturnStub => (), // These edges would leave the function control flow graph.
            }
        }
    }
    None
}

/// Generate a CWE warning for a found CWE hit.
fn generate_cwe_warning(
    source: &str,
    sink: &str,
    source_callsite: Tid,
    sink_callsite: Tid,
    sub_name: &str,
) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Time-of-check Time-of-use Race Condition) '{}' is reachable from '{}' at {} ({}). This could lead to a TOCTOU.",
            sink, source, sink_callsite.address, sub_name
        ))
        .tids(vec![format!("{}", source_callsite), format!("{}", sink_callsite)])
        .addresses(vec![source_callsite.address, sink_callsite.address])
        .symbols(vec![source.into(), sink.into()])
}

/// Run the check. See the module-level documentation for more information.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let project = analysis_results.project;
    let graph = analysis_results.pointer_inference.unwrap().get_graph();
    let mut cwe_warnings = Vec::new();

    let symbol_map: HashMap<&str, Tid> = project
        .program
        .term
        .extern_symbols
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol.tid.clone()))
        .collect();

    for (source, sink) in config.pairs {
        if let (Some(source_tid), Some(sink_tid)) = (
            symbol_map.get(source.as_str()),
            symbol_map.get(sink.as_str()),
        ) {
            for edge in graph.edge_references() {
                if let Edge::ExternCallStub(jmp) = edge.weight() {
                    if let Jmp::Call { target, .. } = &jmp.term {
                        if target == source_tid {
                            if let Some((source_callsite, sink_callsite)) =
                                is_reachable(graph, edge.target(), target, sink_tid)
                            {
                                let sub_name = match graph[edge.target()] {
                                    Node::BlkStart(_blk, sub) => sub.term.name.as_str(),
                                    _ => panic!("Malformed control flow graph."),
                                };
                                cwe_warnings.push(generate_cwe_warning(
                                    source.as_str(),
                                    sink.as_str(),
                                    source_callsite,
                                    sink_callsite,
                                    sub_name,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    (Vec::new(), cwe_warnings)
}
