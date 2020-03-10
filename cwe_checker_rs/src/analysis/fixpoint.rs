/*!
This module implements a generic fixpoint algorithm for dataflow analysis.

A fixpoint problem is defined as a graph where:
- Each node `n` gets assigned a value `val(n)` where the set of all values forms a partially ordered set.
- Each edge `e` defines a rule `e:value -> value` how to compute the value at the end node given the value at the start node of the edge.

A fixpoint is an assignment of values to all nodes of the graph so that for all edges
`e(val(start_node)) <= val(end_node)` holds.

For general information on dataflow analysis using fixpoint algorithms see [Wikipedia](https://en.wikipedia.org/wiki/Data-flow_analysis).
Or open an issue on github that you want more documentation here. :-)
*/

use fnv::FnvHashMap;
use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::{BTreeMap, BinaryHeap};


/// A fixpoint problem defines the context for a fixpoint computation.
///
/// All trait methods have access to the FixpointProblem structure, so that context informations are accessible through it.
pub trait FixpointProblem {
    type EdgeLabel: Clone;
    type NodeValue: PartialEq + Eq;

    /// This function describes how to merge two values
    fn merge(&self, val1: &Self::NodeValue, val2: &Self::NodeValue) -> Self::NodeValue;

    /// This function describes how the value at the end node of an edge is computed from the value at the start node of the edge.
    /// The function can return None to indicate that no end value gets generated through this edge.
    /// E.g. In a control flow graph, if the edge cannot be taken for the given start value, this function should return None.
    fn update_edge(
        &self,
        value: &Self::NodeValue,
        edge: &Self::EdgeLabel,
    ) -> Option<Self::NodeValue>;
}

/// The solution struct contains an intermediate result of a fixpoint computation.
struct Solution<'a, T: FixpointProblem> {
    graph: &'a DiGraph<(), T::EdgeLabel>,
    fp_problem: T,
    node_priority_list: Vec<usize>, // maps a node index to its priority (higher priority nodes get stabilized first)
    priority_to_node_list: Vec<NodeIndex>, // maps a priority to the corresponding node index
    worklist: BinaryHeap<usize>,
    default_value: Option<T::NodeValue>,
    node_values: FnvHashMap<NodeIndex, T::NodeValue>,
}

impl<'a, T: FixpointProblem> Solution<'a, T> {
    /// Create a new fixpoint computation from a fixpoint problem, the corresponding graph
    /// and a default value for all nodes if one should exists.
    pub fn new(
        fp_problem: T,
        graph: &'a DiGraph<(), T::EdgeLabel>,
        default_value: Option<T::NodeValue>,
    ) -> Self {
        // order the nodes in weak topological order
        let sorted_nodes: Vec<NodeIndex> = petgraph::algo::kosaraju_scc(&graph)
            .into_iter()
            .flatten()
            .rev()
            .collect();
        let mut node_to_index = BTreeMap::new();
        for (i, node_index) in sorted_nodes.iter().enumerate() {
            node_to_index.insert(node_index, i);
        }
        let node_priority_list: Vec<usize> = node_to_index.values().copied().collect();
        let mut worklist = BinaryHeap::new();
        // If a default value exists, all nodes are added to the worklist. If not, the worklist is empty
        if default_value.is_some() {
            for i in 0..sorted_nodes.len() {
                worklist.push(i);
            }
        }
        Solution {
            graph: graph,
            fp_problem,
            node_priority_list,
            priority_to_node_list: sorted_nodes,
            worklist,
            default_value,
            node_values: FnvHashMap::default(),
        }
    }

    /// Get the value of a node.
    pub fn get_node_value(&self, node: NodeIndex) -> Option<&T::NodeValue> {
        if let Some(ref value) = self.node_values.get(&node) {
            Some(value)
        } else {
            self.default_value.as_ref()
        }
    }

    /// Set the value of a node and add mark the node as not yet stabilized.
    pub fn set_node_value(&mut self, node: NodeIndex, value: T::NodeValue) {
        self.node_values.insert(node, value);
        self.worklist.push(self.node_priority_list[node.index()]);
    }

    /// Merge the value at a node with some new value.
    fn merge_node_value(&mut self, node: NodeIndex, value: T::NodeValue) {
        if let Some(old_value) = self.node_values.get(&node) {
            let merged_value = self.fp_problem.merge(&value, old_value);
            if merged_value != *old_value {
                self.set_node_value(node, merged_value);
            }
        } else {
            self.set_node_value(node, value);
        }
    }

    /// Compute and update the value at the end node of an edge.
    fn update_edge(&mut self, edge: EdgeIndex) {
        let (start_node, end_node) = self.graph.edge_endpoints(edge).expect("Edge not found");
        if let Some(start_val) = self.node_values.get(&start_node) {
            if let Some(new_end_val) = self.fp_problem.update_edge(
                start_val,
                self.graph.edge_weight(edge).expect("Edge not found"),
            ) {
                self.merge_node_value(end_node, new_end_val);
            }
        }
    }

    /// Update all outgoing edges of a node.
    fn update_node(&mut self, node: NodeIndex) {
        let edges: Vec<EdgeIndex> = self
            .graph
            .edges(node)
            .map(|edge_ref| edge_ref.id())
            .collect();
        for edge in edges {
            self.update_edge(edge);
        }
    }

    /// Compute the fixpoint of the fixpoint problem.
    /// Each node will be visited at most max_steps times.
    /// If a node does not stabilize after max_steps visits, the end result will not be a fixpoint but only an intermediate result of a fixpoint computation.
    pub fn compute_with_max_steps(&mut self, max_steps: u64) {
        let mut steps = vec![0; self.graph.node_count()];
        while let Some(priority) = self.worklist.pop() {
            let node = self.priority_to_node_list[priority];
            if steps[node.index()] < max_steps {
                steps[node.index()] += 1;
                self.update_node(node);
            }
        }
    }

    /// Compute the fixpoint of the fixpoint problem.
    /// If the fixpoint algorithm does not converge to a fixpoint, this function will not terminate.
    pub fn compute(&mut self) {
        while let Some(priority) = self.worklist.pop() {
            let node = self.priority_to_node_list[priority];
            self.update_node(node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Problem {}

    impl FixpointProblem for Problem {
        type EdgeLabel = u64;
        type NodeValue = u64;

        fn merge(&self, val1: &Self::NodeValue, val2: &Self::NodeValue) -> Self::NodeValue {
            std::cmp::min(*val1, *val2)
        }

        fn update_edge(
            &self,
            value: &Self::NodeValue,
            edge: &Self::EdgeLabel,
        ) -> Option<Self::NodeValue> {
            Some(value + edge)
        }
    }

    #[test]
    fn fixpoint() {
        let mut graph: DiGraph<(), u64> = DiGraph::new();
        for _i in 0..101 {
            graph.add_node(());
        }
        for i in 0..100 {
            graph.add_edge(NodeIndex::new(i), NodeIndex::new(i + 1), i as u64 % 10 + 1);
        }
        for i in 0..10 {
            graph.add_edge(NodeIndex::new(i * 10), NodeIndex::new(i * 10 + 5), 0);
        }
        graph.add_edge(NodeIndex::new(100), NodeIndex::new(0), 0);

        let mut solution = Solution::new(Problem {}, &graph, None);
        solution.set_node_value(NodeIndex::new(0), 0);
        solution.compute_with_max_steps(20);

        assert_eq!(30, *solution.get_node_value(NodeIndex::new(9)).unwrap());
        assert_eq!(0, *solution.get_node_value(NodeIndex::new(5)).unwrap());
    }
}
