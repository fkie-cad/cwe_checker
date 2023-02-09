//! This module implements propagation of global variables via two fixpoint algorithms on the call graph.
//! For more details see [`propagate_globals`].

use super::AccessPattern;
use super::FunctionSignature;
use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::DomainMap;
use crate::abstract_domain::UnionMergeStrategy;
use crate::analysis::callgraph::get_program_callgraph;
use crate::analysis::callgraph::CallGraph;
use crate::analysis::fixpoint::{Computation, Context};
use crate::intermediate_representation::*;
use std::collections::BTreeMap;
use std::collections::HashSet;

/// The context object for propagating known global variables top-down in the call graph.
struct KnownGlobalsContext<'a> {
    /// The call graph of the program.
    graph: &'a CallGraph<'a>,
}

impl<'a> KnownGlobalsContext<'a> {
    /// Create a new context object.
    fn new(graph: &'a CallGraph<'a>) -> Self {
        KnownGlobalsContext { graph }
    }
}

impl<'a> Context for KnownGlobalsContext<'a> {
    type EdgeLabel = &'a Term<Jmp>;
    type NodeLabel = Tid;
    /// The values at nodes are the sets of known addresses of global variables for that function.
    type NodeValue = HashSet<u64>;

    /// Get the call graph corresponding to the context object.
    fn get_graph(&self) -> &CallGraph<'a> {
        self.graph
    }

    /// The merge function returns the union of the two input sets of global addresses.
    fn merge(&self, set1: &HashSet<u64>, set2: &HashSet<u64>) -> HashSet<u64> {
        let mut result = set1.clone();
        for address in set2 {
            result.insert(*address);
        }
        result
    }

    /// We always propagate all known addresses of global variables along the edges of the call graph.
    fn update_edge(
        &self,
        globals: &HashSet<u64>,
        _edge: petgraph::stable_graph::EdgeIndex,
    ) -> Option<HashSet<u64>> {
        Some(globals.clone())
    }
}

/// For each function in the call graph,
/// compute the set of global addresses that are known to the function itself
/// or at least one function that calls this function (either directly or indirectly).
///
/// This is computed via a fixpoint algorithm on the call graph of the program,
/// where known addresses of global variables are propagated top-down along the edges of the call graph.
fn propagate_known_globals_top_down(
    project: &Project,
    fn_sigs: &BTreeMap<Tid, FunctionSignature>,
) -> BTreeMap<Tid, HashSet<u64>> {
    let graph = get_program_callgraph(&project.program);
    let context = KnownGlobalsContext::new(&graph);
    let mut computation = Computation::new(context, None);

    // Set the start values of all nodes
    for node in graph.node_indices() {
        let fn_tid = &graph[node];
        let fn_sig = &fn_sigs[fn_tid];
        let globals = fn_sig.global_parameters.keys().cloned().collect();
        computation.set_node_value(node, globals);
    }
    // Propagate top-down in the call graph
    computation.compute_with_max_steps(100);
    // Generate results map
    let mut results = BTreeMap::new();
    for node in graph.node_indices() {
        let fn_tid = &graph[node];
        let propagated_globals = computation.get_node_value(node).unwrap();
        results.insert(fn_tid.clone(), propagated_globals.clone());
    }

    results
}

/// The context object for propagating the access patterns of global variables in the call graph.
struct GlobalsPropagationContext<'a> {
    /// The reversed (!) call graph of the program.
    graph: &'a CallGraph<'a>,
    /// A map from TIDs of functions to the set of known addresses of global variables for that function.
    known_globals: &'a BTreeMap<Tid, HashSet<u64>>,
}

impl<'a> GlobalsPropagationContext<'a> {
    /// Create a new [`GlobalsPropagationContext`] object.
    fn new(graph: &'a CallGraph<'a>, known_globals: &'a BTreeMap<Tid, HashSet<u64>>) -> Self {
        GlobalsPropagationContext {
            graph,
            known_globals,
        }
    }
}

impl<'a> Context for GlobalsPropagationContext<'a> {
    type EdgeLabel = &'a Term<Jmp>;
    type NodeLabel = Tid;
    /// The node values for the fixpoint comutation
    /// are maps from addresses of global variables known to the function represented by the node
    /// to the corresponding access pattern of the global variable.
    type NodeValue = DomainMap<u64, AccessPattern, UnionMergeStrategy>;

    /// Get the (reversed!) call graph corresponding to the program
    fn get_graph(&self) -> &CallGraph<'a> {
        self.graph
    }

    /// Merge two maps of known globals by merging the corresponding access patterns.
    fn merge(&self, globals1: &Self::NodeValue, globals2: &Self::NodeValue) -> Self::NodeValue {
        globals1.merge(globals2)
    }

    /// Propagate the access patterns of global variables along the edges of the reversed call graph.
    ///
    /// Access patterns are propagated from callees to callers,
    /// but only for those global variables, that are also known to the caller.
    fn update_edge(
        &self,
        callee_globals: &Self::NodeValue,
        edge: petgraph::stable_graph::EdgeIndex,
    ) -> Option<Self::NodeValue> {
        let (_, target_node) = self.graph.edge_endpoints(edge).unwrap();
        let target_tid = &self.graph[target_node];
        let caller_known_globals = &self.known_globals[target_tid];

        let caller_globals: Self::NodeValue = callee_globals
            .iter()
            .filter_map(|(address, access_pattern)| {
                if caller_known_globals.contains(address) {
                    Some((*address, *access_pattern))
                } else {
                    None
                }
            })
            .collect();

        Some(caller_globals)
    }
}

/// Propagate the access patterns of global variables bottom-up in the call graph.
///
/// Only those global variables (and their access patterns) are propagated,
/// that are known to the caller anyway (i.e. some function upwards in the call graph accesses the global variable).
fn propagate_globals_bottom_up(
    project: &Project,
    known_globals: &BTreeMap<Tid, HashSet<u64>>,
    fn_sigs: &mut BTreeMap<Tid, FunctionSignature>,
) {
    // To propagate bottom-up, we have to reverse the edges in the callgraph
    let mut graph = get_program_callgraph(&project.program);
    graph.reverse();

    let context = GlobalsPropagationContext::new(&graph, known_globals);
    let mut computation = Computation::new(context, None);
    // Set start values for all nodes
    for node in graph.node_indices() {
        let fn_tid = &graph[node];
        let fn_sig = &fn_sigs[fn_tid];
        let globals = fn_sig
            .global_parameters
            .iter()
            .map(|(address, access_pattern)| (*address, *access_pattern))
            .collect();
        computation.set_node_value(node, globals);
    }
    // Compute the fixpoint
    computation.compute_with_max_steps(100);
    if !computation.has_stabilized() {
        panic!("Global parameter propagation algorithm did not stabilize.")
    }
    // Add the propagated globals to the function signatures
    for node in graph.node_indices() {
        let fn_tid = &graph[node];
        let propagated_globals = computation.get_node_value(node).unwrap();
        let fn_globals = &mut fn_sigs.get_mut(fn_tid).unwrap().global_parameters;
        for (address, propagated_access_pattern) in propagated_globals.iter() {
            fn_globals
                .entry(*address)
                .and_modify(|access_pattern| {
                    *access_pattern = access_pattern.merge(propagated_access_pattern);
                })
                .or_insert(*propagated_access_pattern);
        }
    }
}

/// Propagate the access patterns of global variables along the edges of the call graph of the given project.
///
/// The propagation works as follows:
/// Global variables and their access patterns are only propagated from callees to callers
/// and only if some function upwards in the call-stack also accesses the corresponding variable.
/// As usual, access patterns are merged if the caller also may access a global variable.
///
/// This propagation scheme is optimized for usage with other bottom-up analyses:
/// - If some callee of a function accesses the same global variable as the function itself,
///   then we need to propagate the corresponding access pattern to the function.
///   This ensures that the function knows which callees may modify the value of the global variable.
/// - If two callees of a function access a global variable,
///   then there is no information flow on the value of the global variable between the callees in a proper bottom-up analysis.
///   But if the function itself (or any of its callers) do not access the global variable,
///   then there is no benefit in tracking its value for the function itself.
///   Thus, the global variable should not be propagated to the function in such a case.
pub fn propagate_globals(project: &Project, fn_sigs: &mut BTreeMap<Tid, FunctionSignature>) {
    let known_globals = propagate_known_globals_top_down(project, fn_sigs);
    propagate_globals_bottom_up(project, &known_globals, fn_sigs);
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_globals_propagation() {
        let mut project = Project::mock_arm32();
        // Add 3 functions, so that the call graph will look like this:
        // main -> callee1 -> callee2
        let mut func = Sub::mock("main");
        let mut call_blk = Blk::mock_with_tid("main_blk");
        let call = Jmp::call("call_callee1", "callee1", None);
        call_blk.term.jmps.push(call);
        func.term.blocks.push(call_blk);
        project.program.term.subs.insert(Tid::new("main"), func);

        let mut func = Sub::mock("callee1");
        let mut call_blk = Blk::mock_with_tid("callee1_blk");
        let call = Jmp::call("call_callee2", "callee2", None);
        call_blk.term.jmps.push(call);
        func.term.blocks.push(call_blk);
        project.program.term.subs.insert(Tid::new("callee1"), func);

        let func = Sub::mock("callee2");
        project.program.term.subs.insert(Tid::new("callee2"), func);

        // Add one global var that is known to main and callee2
        // and another that is only known to callee1
        let mut sig_main = FunctionSignature::new();
        sig_main
            .global_parameters
            .insert(1000, AccessPattern::new().with_read_flag());
        let mut sig_callee1 = FunctionSignature::new();
        sig_callee1
            .global_parameters
            .insert(2000, AccessPattern::new().with_dereference_flag());
        let mut sig_callee2 = FunctionSignature::new();
        sig_callee2
            .global_parameters
            .insert(1000, AccessPattern::new_unknown_access());
        let mut fn_sigs = BTreeMap::from([
            (Tid::new("main"), sig_main),
            (Tid::new("callee1"), sig_callee1),
            (Tid::new("callee2"), sig_callee2),
        ]);

        // Propagate globals
        propagate_globals(&project, &mut fn_sigs);
        // Check propagation results
        assert_eq!(
            &fn_sigs[&Tid::new("main")].global_parameters,
            &HashMap::from([(1000, AccessPattern::new_unknown_access())])
        );
        assert_eq!(
            &fn_sigs[&Tid::new("callee1")].global_parameters,
            &HashMap::from([
                (1000, AccessPattern::new_unknown_access()),
                (2000, AccessPattern::new().with_dereference_flag())
            ])
        );
        assert_eq!(
            &fn_sigs[&Tid::new("callee2")].global_parameters,
            &HashMap::from([(1000, AccessPattern::new_unknown_access())])
        );
    }
}
