//! Generate call graphs out of a program term.

use crate::intermediate_representation::*;
use petgraph::{graph::DiGraph, graph::NodeIndex, visit::EdgeRef};
use std::collections::{BTreeSet, HashMap};

/// The graph type of a call graph
pub type CallGraph<'a> = DiGraph<Tid, &'a Term<Jmp>>;

/// Generate a call graph for the given program.
///
/// The nodes of the returned graph correspond to the TIDs of functions in the program.
/// Edges are jump terms of call operations.
///
/// Note that calls to external symbols are not represented in the graph,
/// i.e. there are neither nodes nor edges representing (calls to) external symbols in the graph.
/// Also, there are currently no edges for indirect calls,
/// because a corresponding analysis for resolving indirect calls is not implemented yet.
pub fn get_program_callgraph(program: &Term<Program>) -> CallGraph {
    let mut callgraph = CallGraph::new();
    let mut tid_to_node_index_map = HashMap::new();
    for sub_tid in program.term.subs.keys() {
        let node_index = callgraph.add_node(sub_tid.clone());
        tid_to_node_index_map.insert(sub_tid.clone(), node_index);
    }
    for sub in program.term.subs.values() {
        let source_index = tid_to_node_index_map.get(&sub.tid).unwrap();
        for block in &sub.term.blocks {
            for jump in &block.term.jmps {
                if let Jmp::Call { target, .. } = &jump.term {
                    if let Some(target_index) = tid_to_node_index_map.get(target) {
                        callgraph.add_edge(*source_index, *target_index, jump);
                    }
                }
            }
        }
    }

    callgraph
}

/// Collect and return all call TIDs of call sequences that start in the function given by the `source_sub_tid`
/// and end in the function given by the `target_sub_tid`.
pub fn find_call_sequences_to_target(
    callgraph: &CallGraph,
    source_sub_tid: &Tid,
    target_sub_tid: &Tid,
) -> BTreeSet<Tid> {
    let source_node = callgraph
        .node_indices()
        .find(|node| callgraph[*node] == *source_sub_tid)
        .unwrap_or_else(|| panic!("Function TID not found in call graph."));
    let target_node = callgraph
        .node_indices()
        .find(|node| callgraph[*node] == *target_sub_tid)
        .unwrap_or_else(|| panic!("Function TID not found in call graph."));
    find_call_sequences_from_node_to_target(callgraph, source_node, target_node)
}

/// Collect all call TIDs of calls contained in path in the call graph starting at the source node and ending at the target node.
fn find_call_sequences_from_node_to_target(
    callgraph: &CallGraph,
    source_node: NodeIndex,
    target_node: NodeIndex,
) -> BTreeSet<Tid> {
    use petgraph::Direction;
    // Find all edges on paths starting at source_node using depth-first-search
    let mut nodes_reachable_from_source = BTreeSet::new();
    let mut edges_reachable_from_source = BTreeSet::new();
    let mut stack = vec![source_node];
    while let Some(node) = stack.pop() {
        if nodes_reachable_from_source.insert(node) {
            for neighbor in callgraph.neighbors_directed(node, Direction::Outgoing) {
                stack.push(neighbor);
            }
            for edge in callgraph.edges_directed(node, Direction::Outgoing) {
                edges_reachable_from_source.insert(edge.id());
            }
        }
    }
    // Find all edges on paths leading to target_node using depth-first-search
    let mut nodes_on_paths_to_target = BTreeSet::new();
    let mut edges_on_paths_to_target = BTreeSet::new();
    let mut stack = vec![target_node];
    while let Some(node) = stack.pop() {
        if nodes_on_paths_to_target.insert(node) {
            for neighbor in callgraph.neighbors_directed(node, petgraph::Direction::Incoming) {
                stack.push(neighbor);
            }
            for edge in callgraph.edges_directed(node, Direction::Incoming) {
                edges_on_paths_to_target.insert(edge.id());
            }
        }
    }
    // Compute the intersection of both edge sets and return the corresponding call TIDs
    edges_reachable_from_source
        .iter()
        .filter_map(|edge| {
            if edges_on_paths_to_target.contains(edge) {
                Some(callgraph[*edge].tid.clone())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Mock a function with calls to the given list of Sub-TIDs.
    /// Each call gets a unique ID, so that the edges in the call graph will be distinguishable.
    fn mock_sub_with_calls(sub_tid: &str, call_targets: &[&str]) -> Term<Sub> {
        let mut sub = Sub::mock(sub_tid);
        for (i, target) in call_targets.iter().enumerate() {
            let call = Jmp::Call {
                target: Tid::new(target),
                return_: None,
            };
            let mut block = Blk::mock();
            block.term.jmps.push(Term {
                tid: Tid::new(format!("{}_call_{}_{}", sub_tid, target, i)),
                term: call,
            });
            sub.term.blocks.push(block);
        }
        sub
    }

    #[test]
    fn test_find_call_sequences_to_target() {
        let mut project = Project::mock_x64();
        let sub1 = mock_sub_with_calls("sub1", &["sub2", "sub2"]);
        let sub2 = mock_sub_with_calls("sub2", &["sub3", "sub4"]);
        let sub3 = mock_sub_with_calls("sub3", &[]);
        let sub4 = mock_sub_with_calls("sub4", &[]);
        project.program.term.subs = BTreeMap::from([
            (Tid::new("sub1"), sub1),
            (Tid::new("sub2"), sub2),
            (Tid::new("sub3"), sub3),
            (Tid::new("sub4"), sub4),
        ]);
        let callgraph = get_program_callgraph(&project.program);
        let call_tids =
            find_call_sequences_to_target(&callgraph, &Tid::new("sub1"), &Tid::new("sub3"));
        let call_tids: Vec<_> = call_tids.iter().map(|tid| format!("{}", tid)).collect();
        assert_eq!(call_tids.len(), 3);
        // Note that the order of elements is important in the sense that it needs to be deterministic.
        assert_eq!(&call_tids[0], "sub1_call_sub2_0");
        assert_eq!(&call_tids[1], "sub1_call_sub2_1");
        assert_eq!(&call_tids[2], "sub2_call_sub3_0");
    }

    #[test]
    fn test_get_program_callgraph() {
        // Create a program with 2 functions and one call between them
        let mut project = Project::mock_x64();
        let caller = mock_sub_with_calls("caller", &["callee"]);
        let callee = mock_sub_with_calls("callee", &[]);
        project.program.term.subs.insert(Tid::new("caller"), caller);
        project.program.term.subs.insert(Tid::new("callee"), callee);
        // Test correctness of the call graph
        let callgraph = get_program_callgraph(&project.program);
        assert_eq!(callgraph.node_indices().len(), 2);
        assert_eq!(callgraph.edge_indices().len(), 1);
        let (start, end) = callgraph
            .edge_endpoints(callgraph.edge_indices().next().unwrap())
            .unwrap();
        assert_eq!(callgraph[start], Tid::new("caller"));
        assert_eq!(callgraph[end], Tid::new("callee"));
    }
}
