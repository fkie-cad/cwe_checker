use super::interprocedural_fixpoint::{Computation, NodeValue};
use crate::prelude::*;
use crate::term::*;
use crate::utils::log::CweWarning;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;

mod data;
mod identifier;
mod object;
mod object_list;
mod state;
mod context;

use state::State;
use context::Context;

pub struct PointerInference<'a> {
    computation: Computation<'a, Context<'a>>,
}

impl<'a> PointerInference<'a> {
    pub fn new(project: &'a Project, cwe_sender: crossbeam_channel::Sender<CweWarning>) -> PointerInference<'a> {
        let context = Context::new(project, cwe_sender);

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
                if let Some(entry_block) = sub.term.blocks.iter().next() {
                    entry_sub_to_entry_blocks_map.insert(sub_tid, entry_block.tid.clone());
                }
            }
        }
        let tid_to_graph_indices_map = super::graph::get_indices_of_block_nodes(
            &context.graph,
            entry_sub_to_entry_blocks_map.values(),
        );
        let entry_sub_to_entry_node_map: HashMap<Tid, NodeIndex> = entry_sub_to_entry_blocks_map
            .into_iter()
            .filter_map(|(sub_tid, block_tid)| {
                if let Some((start_node_index, end_node_index)) =
                    tid_to_graph_indices_map.get(&block_tid)
                {
                    Some((sub_tid.clone(), start_node_index.clone()))
                } else {
                    None
                }
            })
            .collect();
        let mut fixpoint_computation =
            super::interprocedural_fixpoint::Computation::new(context, None);
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
        }
    }

    pub fn compute(&mut self) {
        self.computation.compute_with_max_steps(100); // TODO: make max_steps configurable!
    }

    pub fn print_yaml(&self) {
        // Print results serialized as YAML to stdout
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
}

pub fn run(project: &Project, print_debug: bool) -> Vec<CweWarning> {
    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let warning_collector_thread = std::thread::spawn(move || {collect_cwe_warnings(cwe_receiver)});

    {   // Scope the computation object so that it is dropped before the warning collector thread is joined.
        // Else the warning collector thread will not terminate (the cwe_sender needs to be dropped for it to terminate).
        let mut computation = PointerInference::new(project, cwe_sender);

        computation.compute();
        if print_debug {
            computation.print_compact_json();
        }
    }
    // Return the CWE warnings
    warning_collector_thread.join().unwrap()
}

fn collect_cwe_warnings(receiver: crossbeam_channel::Receiver<CweWarning>) -> Vec<CweWarning> {
    let mut collected_warnings = HashMap::new();
    while let Ok(warning) = receiver.recv() {
        match &warning.addresses[..] {
            [] => unimplemented!(),
            [address, ..] => { collected_warnings.insert(address.clone(), warning); },
        }
    }
    collected_warnings.drain().map(|(_key, value)| {value}).collect()
}
