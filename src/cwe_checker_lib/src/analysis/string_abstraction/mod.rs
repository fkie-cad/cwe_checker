//! A fixpoint analysis that abstracts strings in the program using various string abstract domains.
//! These include the Character Inclusion Domain and Bricks Domain among others.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
};

use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop},
    intermediate_representation::{Project, Sub},
    prelude::*,
    utils::binary::RuntimeMemoryImage,
};

use self::state::State;

use super::{
    fixpoint::Computation,
    forward_interprocedural_fixpoint::GeneralizedContext,
    graph::{Graph, Node},
    interprocedural_fixpoint_generic::NodeValue,
    pointer_inference::PointerInference as PointerInferenceComputation,
};

pub mod context;
pub mod state;

use context::*;
use petgraph::Direction;
use petgraph::{graph::NodeIndex, visit::IntoNodeReferences};

/// Configurable parameters for the analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Names of extern functions that manipulate strings
    /// or could introduce new strings (e.g. scanf).
    pub string_symbols: Vec<String>,
    pub format_string_index: BTreeMap<String, usize>,
}

/// A wrapper struct for the string abstraction computation object.
pub struct StringAbstraction<
    'a,
    T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug,
> {
    computation: Computation<GeneralizedContext<'a, Context<'a, T>>>,
}

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug>
    StringAbstraction<'a, T>
{
    /// Generate a new string abstraction computation for a project.
    pub fn new(
        project: &'a Project,
        runtime_memory_image: &'a RuntimeMemoryImage,
        control_flow_graph: &'a Graph<'a>,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        config: Config,
    ) -> StringAbstraction<'a, T> {
        let context = Context::new(
            project,
            runtime_memory_image,
            pointer_inference_results,
            config,
        );

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
        for node in control_flow_graph.node_indices() {
            if let super::graph::Node::BlkStart(block, sub) = control_flow_graph[node] {
                tid_to_graph_indices_map.insert((block.tid.clone(), sub.tid.clone()), node);
            }
        }
        let entry_sub_to_entry_node_map: HashMap<Tid, NodeIndex> = entry_sub_to_entry_blocks_map
            .into_iter()
            .filter_map(|(sub_tid, block_tid)| {
                if let Some(start_node_index) =
                    tid_to_graph_indices_map.get(&(block_tid, sub_tid.clone()))
                {
                    // We only add entry points that are also control flow graph roots
                    if control_flow_graph
                        .neighbors_directed(*start_node_index, Direction::Incoming)
                        .next()
                        .is_none()
                    {
                        Some((sub_tid.clone(), *start_node_index))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let mut fixpoint_computation =
            super::forward_interprocedural_fixpoint::create_computation(context, None);

        for (_, start_node_index) in entry_sub_to_entry_node_map.into_iter() {
            fixpoint_computation.set_node_value(
                start_node_index,
                super::interprocedural_fixpoint_generic::NodeValue::Value(State::new(
                    start_node_index,
                    pointer_inference_results,
                )),
            );
        }

        let mut abstr = StringAbstraction {
            computation: fixpoint_computation,
        };

        abstr.add_speculative_entry_points(project, false);

        abstr
    }

    /// Compute the fixpoint of the string abstraction analysis.
    /// Has a `max_steps` bound for the fixpoint algorithm to prevent infinite loops.
    pub fn compute(&mut self) {
        self.computation.compute_with_max_steps(100); // TODO: make max_steps configurable!
    }

    pub fn get_computation(&self) -> &Computation<GeneralizedContext<'a, Context<'a, T>>> {
        &self.computation
    }

    /// Get the underlying graph of the computation.
    pub fn get_graph(&self) -> &Graph {
        self.computation.get_graph()
    }

    /// Get the context object of the computation.
    pub fn get_context(&self) -> &Context<'a, T> {
        self.computation.get_context().get_context()
    }

    /// Get the value associated to a node in the computed fixpoint
    /// (or intermediate state of the algorithm if the fixpoint has not been reached yet).
    /// Returns `None` if no value is associated to the Node.
    pub fn get_node_value(&self, node_id: NodeIndex) -> Option<&NodeValue<State<T>>> {
        self.computation.get_node_value(node_id)
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
                    /*if sub.tid.address == "00013798" {
                        new_entry_points.push(node_id);
                    }*/

                    new_entry_points.push(node_id);
                }
            }
        }
        for entry in new_entry_points {
            self.computation.set_node_value(
                entry,
                super::interprocedural_fixpoint_generic::NodeValue::Value(State::new(
                    entry,
                    self.get_context().pointer_inference_results,
                )),
            );
        }
    }
}

/// Compute the pointer inference analysis and return its results.
///
/// If `print_debug` is set to `true` print debug information to *stdout*.
/// Note that the format of the debug information is currently unstable and subject to change.
pub fn run<'a, T: AbstractDomain + HasTop + Eq + From<String> + DomainInsertion + Debug>(
    project: &'a Project,
    runtime_memory_image: &'a RuntimeMemoryImage,
    control_flow_graph: &'a Graph<'a>,
    pointer_inference: &'a PointerInferenceComputation<'a>,
    config: Config,
) -> StringAbstraction<'a, T> {
    StringAbstraction::new(
        project,
        runtime_memory_image,
        control_flow_graph,
        pointer_inference,
        config,
    )
}

#[cfg(test)]
pub mod tests;
