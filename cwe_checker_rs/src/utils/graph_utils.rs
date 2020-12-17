use crate::analysis::graph::*;
use crate::intermediate_representation::Jmp;
use crate::prelude::*;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::HashSet;

/// Check whether a call to the `sink_symbol` is reachable from the given `source_node`
/// through a path of intraprocedural edges in the control flow graph.
///
/// A simple depth-first-search on the graph is used to find such a path.
/// We do not search past subsequent calls to the `source_symbol`
/// since we assume that sink calls after that belong to the new call to the source symbol and not the original one.
///
/// If a sink is found, the `Tid` of the jump term calling the sink is returned.
pub fn is_sink_call_reachable_from_source_call(
    graph: &Graph,
    source_node: NodeIndex,
    source_symbol: &Tid,
    sink_symbol: &Tid,
) -> Option<Tid> {
    let mut visited_nodes = HashSet::new();
    visited_nodes.insert(source_node);
    let mut worklist = vec![source_node];

    while let Some(node) = worklist.pop() {
        for edge in graph.edges(node) {
            if let Edge::ExternCallStub(jmp) = edge.weight() {
                if let Jmp::Call { target, .. } = &jmp.term {
                    if target == sink_symbol {
                        // We found a call to the sink
                        return Some(jmp.tid.clone());
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
