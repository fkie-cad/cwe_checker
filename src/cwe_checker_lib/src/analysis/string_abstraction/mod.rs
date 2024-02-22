//! A fixpoint analysis that abstracts strings in the program using various string abstract domains.
//! These include the Character Inclusion Domain and Bricks Domain among others.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
};

use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop},
    intermediate_representation::Project,
    prelude::*,
};

use self::state::State;

use super::{
    fixpoint::Computation, forward_interprocedural_fixpoint::GeneralizedContext, graph::Graph,
    interprocedural_fixpoint_generic::NodeValue,
    pointer_inference::PointerInference as PointerInferenceComputation,
};

pub mod context;
pub mod state;

use context::*;
use petgraph::graph::NodeIndex;

/// Configurable parameters for the analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Names of extern functions that manipulate strings
    /// or could introduce new strings (e.g. scanf).
    pub string_symbols: Vec<String>,
    /// The index of the format string parameter in the function signature
    /// of an external symbol.
    pub format_string_index: BTreeMap<String, usize>,
}

/// A wrapper struct for the string abstraction computation object.
pub struct StringAbstraction<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> {
    computation: Computation<GeneralizedContext<'a, Context<'a, T>>>,
}

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>>
    StringAbstraction<'a, T>
{
    /// Generate a new string abstraction computation for a project.
    pub fn new(
        project: &'a Project,
        control_flow_graph: &'a Graph<'a>,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        config: Config,
    ) -> StringAbstraction<'a, T> {
        let context = Context::new(project, pointer_inference_results, config);

        let mut sub_to_entry_blocks_map = HashMap::new();
        for sub in project.program.term.subs.values() {
            if let Some(entry_block) = sub.term.blocks.first() {
                sub_to_entry_blocks_map.insert(sub.tid.clone(), entry_block.tid.clone());
            }
        }
        let mut tid_to_graph_indices_map = HashMap::new();
        for node in control_flow_graph.node_indices() {
            if let super::graph::Node::BlkStart(block, sub) = control_flow_graph[node] {
                tid_to_graph_indices_map.insert((block.tid.clone(), sub.tid.clone()), node);
            }
        }
        let sub_to_entry_node_map: HashMap<Tid, NodeIndex> = sub_to_entry_blocks_map
            .into_iter()
            .filter_map(|(sub_tid, block_tid)| {
                tid_to_graph_indices_map
                    .get(&(block_tid, sub_tid.clone()))
                    .map(|start_node_index| (sub_tid, *start_node_index))
            })
            .collect();

        let mut fixpoint_computation =
            super::forward_interprocedural_fixpoint::create_computation(context, None);

        for (_, start_node_index) in sub_to_entry_node_map.into_iter() {
            fixpoint_computation.set_node_value(
                start_node_index,
                super::interprocedural_fixpoint_generic::NodeValue::Value(State::new(
                    start_node_index,
                    pointer_inference_results,
                )),
            );
        }

        StringAbstraction {
            computation: fixpoint_computation,
        }
    }

    /// Compute the fixpoint of the string abstraction analysis.
    /// Has a `max_steps` bound for the fixpoint algorithm to prevent infinite loops.
    pub fn compute(&mut self) {
        self.computation.compute_with_max_steps(100); // TODO: make max_steps configurable!
    }

    /// Get the string abstraction computation.
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
}

/// Compute the string abstraction and return its results.
pub fn run<'a, T: AbstractDomain + HasTop + Eq + From<String> + DomainInsertion>(
    project: &'a Project,
    control_flow_graph: &'a Graph<'a>,
    pointer_inference: &'a PointerInferenceComputation<'a>,
    config: Config,
) -> StringAbstraction<'a, T> {
    let mut string_abstraction =
        StringAbstraction::new(project, control_flow_graph, pointer_inference, config);

    string_abstraction.compute();

    string_abstraction
}

#[cfg(test)]
pub mod tests;
