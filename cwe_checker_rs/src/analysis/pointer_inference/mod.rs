//! The pointer inference analysis.
//!
//! The goal of the pointer inference analysis is to keep track of all memory objects and pointers
//! that the program knows about at specific program points during execution.
//! Possible memory management errors, like access to memory that may already have been freed,
//! are reported to the user.
//!
//! Keep in mind that the analysis operates on a best-effort basis.
//! In cases where we cannot know
//! whether an error is due to an error in the memory management of the program under analysis
//! or due to inexactness of the pointer inference analysis itself,
//! we try to treat is as the more likely (but not necessarily true) case of the two.
//!
//! See the `Config` struct for configurable analysis parameters.

use super::interprocedural_fixpoint::{Computation, NodeValue};
use crate::abstract_domain::{BitvectorDomain, DataDomain};
use crate::analysis::graph::{Graph, Node};
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::*;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use petgraph::Direction;
use std::collections::HashMap;

mod context;
mod object;
mod object_list;
mod state;

use context::Context;
pub use state::State;

/// The version number of the analysis.
const VERSION: &str = "0.1";

pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "Memory",
    version: VERSION,
    run: run_analysis,
};

/// The abstract domain type for representing register values.
type Data = DataDomain<BitvectorDomain>;

/// Configurable parameters for the analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Names of extern functions that are `malloc`-like,
    /// i.e. the unique return value is a pointer to a newly allocated chunk of memory or a NULL pointer.
    allocation_symbols: Vec<String>,
    /// Names of extern functions that are `free`-like,
    /// i.e. the memory chunk that the unique parameter of the function points to gets deallocated.
    /// Note that the analysis currently does not detect mismatching allocation-deallocation pairs,
    /// i.e. it cannot distinguish between memory allocated by `malloc` and memory allocated by `new`.
    deallocation_symbols: Vec<String>,
}

/// A wrapper struct for the pointer inference computation object.
pub struct PointerInference<'a> {
    computation: Computation<'a, Context<'a>>,
    log_collector: crossbeam_channel::Sender<LogMessage>,
}

impl<'a> PointerInference<'a> {
    /// Generate a new pointer inference compuation for a project.
    pub fn new(
        project: &'a Project,
        config: Config,
        cwe_sender: crossbeam_channel::Sender<CweWarning>,
        log_sender: crossbeam_channel::Sender<LogMessage>,
    ) -> PointerInference<'a> {
        let context = Context::new(project, config, cwe_sender, log_sender.clone());

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
                    entry_sub_to_entry_blocks_map.insert(sub_tid, entry_block.tid.clone());
                }
            }
        }
        let mut tid_to_graph_indices_map = HashMap::new();
        for node in context.graph.node_indices() {
            if let super::graph::Node::BlkStart(block, sub) = context.graph[node] {
                tid_to_graph_indices_map.insert((block.tid.clone(), sub.tid.clone()), node);
            }
        }
        let entry_sub_to_entry_node_map: HashMap<Tid, NodeIndex> = entry_sub_to_entry_blocks_map
            .into_iter()
            .filter_map(|(sub_tid, block_tid)| {
                if let Some(start_node_index) =
                    tid_to_graph_indices_map.get(&(block_tid, sub_tid.clone()))
                {
                    Some((sub_tid.clone(), *start_node_index))
                } else {
                    None
                }
            })
            .collect();
        let mut fixpoint_computation =
            super::interprocedural_fixpoint::Computation::new(context, None);
        log_sender
            .send(LogMessage::new_debug(format!(
                "Pointer Inference: Adding {} entry points",
                entry_sub_to_entry_node_map.len()
            )))
            .unwrap();
        for (sub_tid, start_node_index) in entry_sub_to_entry_node_map.into_iter() {
            fixpoint_computation.set_node_value(
                start_node_index,
                super::interprocedural_fixpoint::NodeValue::Value(State::new(
                    &project.stack_pointer_register,
                    sub_tid,
                )),
            );
        }
        PointerInference {
            computation: fixpoint_computation,
            log_collector: log_sender,
        }
    }

    /// Compute the fixpoint of the pointer inference analysis.
    /// Has a `max_steps` bound for the fixpoint algorithm to prevent infinite loops.
    pub fn compute(&mut self) {
        self.computation.compute_with_max_steps(100); // TODO: make max_steps configurable!
    }

    /// Print results serialized as YAML to stdout
    pub fn print_yaml(&self) {
        let graph = self.computation.get_graph();
        for (node_index, value) in self.computation.node_values().iter() {
            let node = graph.node_weight(*node_index).unwrap();
            if let Ok(string) = serde_yaml::to_string(&(node, value)) {
                println!("{}", string);
            } else {
                println!(
                    "Serializing failed at {:?} with {:?}",
                    node_index,
                    serde_yaml::to_string(value)
                );
            }
        }
    }

    /// Generate a compacted json representation of the results.
    /// Note that this output cannot be used for serialization/deserialization,
    /// but is only intended for user output.
    pub fn generate_compact_json(&self) -> serde_json::Value {
        let graph = self.computation.get_graph();
        let mut json_nodes = serde_json::Map::new();
        for (node_index, node_value) in self.computation.node_values().iter() {
            let node = graph.node_weight(*node_index).unwrap();
            if let NodeValue::Value(value) = node_value {
                json_nodes.insert(format!("{}", node), value.to_json_compact());
            }
        }
        serde_json::Value::Object(json_nodes)
    }

    pub fn print_compact_json(&self) {
        println!("{:#}", self.generate_compact_json());
    }

    pub fn get_graph(&self) -> &Graph {
        self.computation.get_graph()
    }

    /// Add speculative entry points to the fixpoint algorithm state.
    ///
    /// Since indirect jumps and calls are not handled yet (TODO: change that),
    /// the analysis may miss a *lot* of code in some cases.
    /// To remedy this somewhat,
    /// we mark all function starts, that are also roots in the control flow graph
    /// and do not have a state assigned to them yet, as additional entry points.
    ///
    /// If `only_cfg_roots` is set to `false`, then all function starts without a state are marked as roots.
    fn add_speculative_entry_points(&mut self, project: &Project, only_cfg_roots: bool) {
        // TODO: Refactor the fixpoint computation structs, so that the project reference can be extracted from them.
        let mut start_block_to_sub_map: HashMap<&Tid, &Term<Sub>> = HashMap::new();
        for sub in project.program.term.subs.iter() {
            if project
                .program
                .term
                .extern_symbols
                .iter()
                .any(|symbol| symbol.tid == sub.tid)
            {
                continue; // We ignore functions marked as extern symbols.
            }
            if let Some(start_block) = sub.term.blocks.first() {
                start_block_to_sub_map.insert(&start_block.tid, sub);
            }
        }
        let graph = self.computation.get_graph();
        let mut new_entry_points = Vec::new();
        for (node_id, node) in graph.node_references() {
            if let Node::BlkStart(block, sub) = node {
                if start_block_to_sub_map.get(&block.tid) == Some(sub)
                    && self.computation.get_node_value(node_id).is_none()
                    && (!only_cfg_roots
                        || graph
                            .neighbors_directed(node_id, Direction::Incoming)
                            .next()
                            .is_none())
                {
                    new_entry_points.push(node_id);
                }
            }
        }
        self.log_debug(format!(
            "Pointer Inference: Adding {} speculative entry points",
            new_entry_points.len()
        ));
        for entry in new_entry_points {
            let sub_tid = start_block_to_sub_map
                [&self.computation.get_graph()[entry].get_block().tid]
                .tid
                .clone();
            self.computation.set_node_value(
                entry,
                super::interprocedural_fixpoint::NodeValue::Value(State::new(
                    &project.stack_pointer_register,
                    sub_tid,
                )),
            );
        }
    }

    /// Print the number of blocks that have a state associated to them.
    /// Intended for debug purposes.
    fn count_blocks_with_state(&self) {
        let graph = self.computation.get_graph();
        let mut stateful_blocks: i64 = 0;
        let mut all_blocks: i64 = 0;
        for (node_id, node) in graph.node_references() {
            if let Node::BlkStart(_block, _sub) = node {
                all_blocks += 1;
                if self.computation.get_node_value(node_id).is_some() {
                    stateful_blocks += 1;
                }
            }
        }
        self.log_debug(format!(
            "Pointer Inference: Blocks with state: {} / {}",
            stateful_blocks, all_blocks
        ));
    }

    fn log_debug(&self, msg: impl Into<String>) {
        let log_msg = LogMessage::new_debug(msg.into());
        self.log_collector.send(log_msg).unwrap();
    }
}

/// The main entry point for executing the pointer inference analysis.
pub fn run_analysis(
    project: &Project,
    analysis_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(analysis_params.clone()).unwrap();
    run(project, config, false)
}

/// Generate and execute the pointer inference analysis.
/// Returns a vector of all found CWE warnings and a vector of all log messages generated during analysis.
pub fn run(
    project: &Project,
    config: Config,
    print_debug: bool,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();
    let (log_sender, log_receiver) = crossbeam_channel::unbounded();

    let warning_collector_thread = std::thread::spawn(move || collect_cwe_warnings(cwe_receiver));
    let log_collector_thread = std::thread::spawn(move || collect_logs(log_receiver));

    {
        // Scope the computation object so that it is dropped before the warning collector thread is joined.
        // Else the warning collector thread will not terminate (the cwe_sender needs to be dropped for it to terminate).
        let mut computation = PointerInference::new(project, config, cwe_sender, log_sender);

        computation.compute();
        computation.count_blocks_with_state();

        // Now compute again with speculative entry points added
        computation.add_speculative_entry_points(project, true);
        computation.compute();
        computation.count_blocks_with_state();

        // Now compute again with all missed functions as additional entry points
        computation.add_speculative_entry_points(project, false);
        computation.compute();
        computation.count_blocks_with_state();

        if print_debug {
            computation.print_compact_json();
        }
    }
    // Return the CWE warnings
    (
        log_collector_thread.join().unwrap(),
        warning_collector_thread.join().unwrap(),
    )
}

/// Collect CWE warnings from the receiver until the channel is closed. Then return them.
fn collect_cwe_warnings(receiver: crossbeam_channel::Receiver<CweWarning>) -> Vec<CweWarning> {
    let mut collected_warnings = HashMap::new();
    while let Ok(warning) = receiver.recv() {
        match &warning.addresses[..] {
            [] => unimplemented!(),
            [address, ..] => {
                collected_warnings.insert(address.clone(), warning);
            }
        }
    }
    collected_warnings
        .drain()
        .map(|(_key, value)| value)
        .collect()
}

/// Collect log messages from the receiver until the channel is closed. Then return them.
fn collect_logs(receiver: crossbeam_channel::Receiver<LogMessage>) -> Vec<LogMessage> {
    let mut logs_with_address = HashMap::new();
    let mut general_logs = Vec::new();
    while let Ok(log_message) = receiver.recv() {
        if let Some(ref tid) = log_message.location {
            logs_with_address.insert(tid.address.clone(), log_message);
        } else {
            general_logs.push(log_message);
        }
    }
    logs_with_address
        .values()
        .cloned()
        .chain(general_logs.into_iter())
        .collect()
}
