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
//! Using backward dataflow analysis we search for an executation path from a system call parameter (string) to an user input
//! to identify possible command injections.
//!
//! To find relevant string related functions, such as sprintf, it is assumed that the first input parameter points
//! to the memory position that will be used as the return location. (e.g. char *strcat(char *dest, const char *src)
//! where 'char *dest' will contain the return value)
//!
//! For instance:
//!     ...
//!     MOV RAX, qword ptr [RBP + local_10]
//!     MOV RDI, RAX                        // RDI is the first input parameter for the strcat call and it points to [RBP + local_10]
//!     CALL strcat
//!     MOV RAX, qword ptr [RBP + local_10] // In the backwards analysis [RBP + local_10] will be tainted and it contains the return value
//!     ...
//!
//! ### Symbols configurable in config.json
//!
//! The symbols are the functions which
//!   1. make system calls (e.g. system)
//!   2. manipulate strings (e.g. sprintf, strcat, memcpy, etc.)
//!   3. take user input (e.g. scanf)
//!
//! ## False Positives
//!
//! - The input comes from the user but proper sanitization was not detected by the analysis even though it exists.
//! - The input comes from the user but the format string's input format could not be distinguished as non-string input.
//!
//! ## False Negatives
//!
//! - Missing Taints due to lost track of pointer targets
//! - Non tracked function parameters cause incomplete taints that could miss possible dangerous inputs

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
    /// The names of the string manipulating symbols
    string_symbols: Vec<String>,
    /// The name of the user input symbols
    user_input_symbols: Vec<String>,
}

/// This check searches for system calls and sets their parameters as taint source if available.
/// Then the fixpoint computation is executed and its result may generate cwe warnings if
/// the parameters can be tracked back to user inputs
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pointer_inference_results = analysis_results.pointer_inference.unwrap();

    let mut cwe_78_graph = analysis_results.control_flow_graph.clone();
    cwe_78_graph.reverse();

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let system_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.system_symbols[..]);
    let string_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.string_symbols[..]);
    let user_input_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.user_input_symbols[..]);
    let general_context = Context::new(
        project,
        analysis_results.runtime_memory_image,
        &cwe_78_graph,
        &pointer_inference_results,
        string_symbols,
        user_input_symbols,
        cwe_sender,
    );

    let entry_sub_to_entry_node_map = get_entry_sub_to_entry_node_map(project, &general_context);

    for edge in general_context.get_pi_graph().edge_references() {
        if let Edge::ExternCallStub(jmp) = edge.weight() {
            if let Jmp::Call { target, .. } = &jmp.term {
                if let Some(symbol) = system_symbols.get(target) {
                    let node = edge.source();
                    let current_sub = match general_context.get_pi_graph()[node] {
                        Node::BlkEnd(_blk, sub) => sub,
                        _ => panic!(),
                    };
                    let mut context = general_context.clone();
                    context.set_taint_source(jmp, &symbol.name, current_sub);
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
                            current_sub,
                        )),
                    );
                    computation.compute_with_max_steps(100);

                    for (sub_name, node_index) in entry_sub_to_entry_node_map.iter() {
                        if let Some(node_weight) = computation.get_node_value(*node_index) {
                            let state = node_weight.unwrap_value();
                            if !state.is_empty() {
                                context.generate_cwe_warning(sub_name);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cwe_warnings = HashMap::new();
    for cwe in cwe_receiver.try_iter() {
        match &cwe.addresses[..] {
            [taint_source_address, ..] => cwe_warnings.insert(taint_source_address.clone(), cwe),
            _ => panic!(),
        };
    }
    let cwe_warnings = cwe_warnings.into_iter().map(|(_, cwe)| cwe).collect();

    (Vec::new(), cwe_warnings)
}

/// Returns a map from subroutine names to their corresponding start node index
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
            if let Some(start_node_index) = tid_to_graph_indices_map.get(&(block_tid, sub_tid)) {
                Some((name, *start_node_index))
            } else {
                None
            }
        })
        .collect()
}
