//! Generate call graphs out of a program term.

use std::collections::HashMap;

use crate::intermediate_representation::*;
use petgraph::graph::DiGraph;

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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_get_program_callgraph() {
        // Create a program with 2 functions and one call between them
        let mut project = Project::mock_x64();
        let mut caller = Sub::mock("caller");
        let callee = Sub::mock("callee");
        let call = Jmp::Call {
            target: Tid::new("callee"),
            return_: None,
        };
        let mut call_block = Blk::mock();
        call_block.term.jmps.push(Term {
            tid: Tid::new("call"),
            term: call,
        });
        caller.term.blocks.push(call_block);
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
