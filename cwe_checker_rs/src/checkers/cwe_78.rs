//! This module implements a check for CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection').
//!
//! The software constructs all or part of an OS command using externally-influenced input from an upstream component,
//! but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command
//! when it is sent to a downstream component.
//!
//! See <https://cwe.mitre.org/data/definitions/78.html> for a detailed description.
//!
//! ## How the check works
//!
//! Using dataflow analysis we search for an executation path from a system call parameter (string) to an user input
//! to identify possible command injections.
//!
//! ### Symbols configurable in config.json
//!
//! The symbols are the functions which
//!   1. take user input (e.g. scanf)
//!   2. make system calls (e.g. system)
//!   3. manipulate strings (e.g. sprintf, strcat, memcpy, etc.)
//!   4. check strings for characters (e.g. regexp)
//!
//! ## False Positives
//!
//! - The input comes from the user but proper sanitization was not detected by the analysis even though it exists.
//! - The input comes from the user but the format string's input format could not be distinguised as non-string.
//!
//! ## False Negatives
//!
//! -

use std::collections::HashMap;

use crate::{
    analysis::{
        backward_interprocedural_fixpoint::{create_computation, Context as _},
        graph::{self, Edge, Node},
        interprocedural_fixpoint_generic::NodeValue,
    },
    intermediate_representation::{Jmp, Project, Sub},
    prelude::*,
    utils::log::{CweWarning, LogMessage},
    AnalysisResults, CweModule,
};

use petgraph::{graph::NodeIndex, visit::EdgeRef};
mod state;
use state::*;

mod context;
use context::*;

mod taint;
use taint::*;

pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE78",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// The names of the system call symbols
    system_symbols: Vec<String>,
    string_symbols: Vec<String>,
}

pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pointer_inference_results = analysis_results.pointer_inference.unwrap();

    let (cwe_sender, _cwe_receiver) = crossbeam_channel::unbounded();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let symbol_map =
        crate::utils::symbol_utils::get_symbol_map(project, &config.system_symbols[..]);
    let string_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.string_symbols[..]);
    let general_context = Context::new(
        project,
        &pointer_inference_results,
        string_symbols,
        cwe_sender,
    );

    let entry_sub_to_entry_node_map = get_entry_sub_to_entry_node_map(project, &general_context);

    let mut cwe_warnings: Vec<CweWarning> = Vec::new();

    for edge in general_context.get_pi_graph().edge_references() {
        if let Edge::ExternCallStub(jmp) = edge.weight() {
            if let Jmp::Call { target, .. } = &jmp.term {
                if let Some(symbol) = symbol_map.get(target) {
                    let node = edge.target();
                    let current_sub = match general_context.get_pi_graph()[node] {
                        Node::BlkStart(_blk, sub) => sub,
                        _ => panic!(),
                    };
                    let mut context = general_context.clone();
                    context.set_taint_source(jmp, current_sub);
                    let pi_state_at_taint_source =
                        match pointer_inference_results.get_node_value(node) {
                            Some(NodeValue::Value(val)) => Some(val.clone()),
                            _ => None,
                        };
                    let mut computation = create_computation(context.clone(), None);
                    computation.set_node_value(
                        node,
                        NodeValue::Value(State::new(
                            symbol,
                            &project.stack_pointer_register,
                            pi_state_at_taint_source.as_ref(),
                        )),
                    );
                    computation.compute_with_max_steps(100);

                    let taint_source = context.taint_source.unwrap();
                    let taint_source_name = context.taint_source_name.unwrap();

                    for (sub_name, node_index) in entry_sub_to_entry_node_map.iter() {
                        if let Some(node_weight) = computation.get_node_value(node_index.clone()) {
                            let state = node_weight.unwrap_value();
                            if !state.is_empty() {
                                cwe_warnings.push(generate_cwe_warning(
                                    sub_name,
                                    taint_source.clone(),
                                    taint_source_name.clone(),
                                    state.get_string_constants(),
                                ))
                            }
                        }
                    }
                }
            }
        }
    }

    (Vec::new(), cwe_warnings)
}

fn generate_cwe_warning(
    sub_name: &String,
    source: Term<Jmp>,
    name: String,
    constants: Vec<Bitvector>,
) -> CweWarning {
    let mut param_location = String::new();
    for constant in constants.clone() {
        param_location.push_str(format!("    {}\n", constant.try_to_i64().unwrap()).as_str());
    }
    let description: String = format!(
        "(Potential OS Command Injection) {} ({}) -> {}\n{}",
        sub_name, source.tid.address, name, param_location
    );
    CweWarning::new(
        String::from(CWE_MODULE.name),
        String::from(CWE_MODULE.version),
        description,
    )
    .addresses(vec![source.tid.address.clone()])
    .tids(vec![format!("{}", source.tid)])
    .symbols(vec![String::from(sub_name)])
    .other(vec![vec![
        String::from("OS Command Injection"),
        String::from(name),
    ]])
}

fn get_entry_sub_to_entry_node_map(
    project: &Project,
    context: &Context,
) -> HashMap<String, NodeIndex> {
    let mut entry_sub_to_entry_blocks_map = HashMap::new();
    let subs: HashMap<Tid, &Term<Sub>> = project
        .program
        .term
        .subs
        .iter()
        .map(|sub| (sub.tid.clone(), sub))
        .collect();

    for sub_tid in project.program.term.entry_points.iter() {
        if let Some(sub) = subs.get(sub_tid) {
            if let Some(entry_block) = sub.term.blocks.get(0) {
                entry_sub_to_entry_blocks_map.insert(
                    (sub_tid.clone(), sub.term.name.clone()),
                    entry_block.tid.clone(),
                );
            }
        }
    }
    let mut tid_to_graph_indices_map = HashMap::new();
    for node in context.get_graph().node_indices() {
        if let graph::Node::BlkStart(block, sub) = context.get_graph()[node] {
            tid_to_graph_indices_map.insert((block.tid.clone(), sub.tid.clone()), node);
        }
    }
    entry_sub_to_entry_blocks_map
        .into_iter()
        .filter_map(|((sub_tid, name), block_tid)| {
            if let Some(start_node_index) =
                tid_to_graph_indices_map.get(&(block_tid, sub_tid.clone()))
            {
                Some((name, *start_node_index))
            } else {
                None
            }
        })
        .collect()
}
