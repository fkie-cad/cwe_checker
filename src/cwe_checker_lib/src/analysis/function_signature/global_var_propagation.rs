//! This module implements propagation of global variables via two fixpoint algorithms on the call graph.
//! For more details see [`propagate_globals`].

use super::AccessPattern;
use super::FunctionSignature;
use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::AbstractLocation;
use crate::abstract_domain::DomainMap;
use crate::abstract_domain::UnionMergeStrategy;
use crate::analysis::callgraph::get_program_callgraph;
use crate::analysis::callgraph::CallGraph;
use crate::analysis::fixpoint::{Computation, Context};
use crate::intermediate_representation::*;
use crate::utils::log::LogMessage;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
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
    type NodeValue = BTreeSet<AbstractLocation>;

    /// Get the call graph corresponding to the context object.
    fn get_graph(&self) -> &CallGraph<'a> {
        self.graph
    }

    /// The merge function returns the union of the two input sets of global addresses.
    fn merge(
        &self,
        set1: &BTreeSet<AbstractLocation>,
        set2: &BTreeSet<AbstractLocation>,
    ) -> BTreeSet<AbstractLocation> {
        let mut result = set1.clone();
        for address in set2 {
            result.insert(address.clone());
        }
        result
    }

    /// We always propagate all known addresses of global variables along the edges of the call graph.
    fn update_edge(
        &self,
        globals: &BTreeSet<AbstractLocation>,
        _edge: petgraph::stable_graph::EdgeIndex,
    ) -> Option<BTreeSet<AbstractLocation>> {
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
) -> BTreeMap<Tid, BTreeSet<AbstractLocation>> {
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
    known_globals: &'a BTreeMap<Tid, BTreeSet<AbstractLocation>>,
}

impl<'a> GlobalsPropagationContext<'a> {
    /// Create a new [`GlobalsPropagationContext`] object.
    fn new(
        graph: &'a CallGraph<'a>,
        known_globals: &'a BTreeMap<Tid, BTreeSet<AbstractLocation>>,
    ) -> Self {
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
    /// are maps from locations of (possibly nested) global variables known to the function represented by the node
    /// to the corresponding access pattern of the global variable.
    type NodeValue = DomainMap<AbstractLocation, AccessPattern, UnionMergeStrategy>;

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
                    Some((address.clone(), *access_pattern))
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
    known_globals: &BTreeMap<Tid, BTreeSet<AbstractLocation>>,
    fn_sigs: &mut BTreeMap<Tid, FunctionSignature>,
    logs: &mut Vec<LogMessage>,
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
            .map(|(address, access_pattern)| (address.clone(), *access_pattern))
            .collect();
        computation.set_node_value(node, globals);
    }
    // Compute the fixpoint
    computation.compute_with_max_steps(100);
    if !computation.has_stabilized() {
        let error_msg = format!(
            "Global parameter propagation algorithm did not stabilize. Remaining worklist size: {}",
            computation.get_worklist().len()
        );
        logs.push(LogMessage::new_error(error_msg).source("Function Signature Analysis"));
    }
    // Add the propagated globals to the function signatures
    for node in graph.node_indices() {
        let fn_tid = &graph[node];
        let propagated_globals = computation.get_node_value(node).unwrap();
        let fn_globals = &mut fn_sigs.get_mut(fn_tid).unwrap().global_parameters;
        for (address, propagated_access_pattern) in propagated_globals.iter() {
            fn_globals
                .entry(address.clone())
                .and_modify(|access_pattern| {
                    *access_pattern = access_pattern.merge(propagated_access_pattern);
                })
                .or_insert(*propagated_access_pattern);
        }
    }
}

/// For all nested global parameters add the corresponding parent locations to the function signatures.
///
/// This ensures that subsequent analyses can safely assume
/// that for each nested parameter the parent location is also a parameter.
fn add_parents_of_known_nested_globals(
    fn_sigs: &mut BTreeMap<Tid, FunctionSignature>,
    generic_pointer_size: ByteSize,
) {
    for fn_sig in fn_sigs.values_mut() {
        let mut parents_to_add = HashSet::new();
        for global in fn_sig.global_parameters.keys() {
            parents_to_add.extend(get_parents_of_global(global, generic_pointer_size).into_iter());
        }
        for parent in parents_to_add {
            fn_sig
                .global_parameters
                .entry(parent)
                .and_modify(|pattern| pattern.set_dereference_flag())
                .or_insert(
                    AccessPattern::new()
                        .with_read_flag()
                        .with_dereference_flag(),
                );
        }
    }
}

/// get all parent locations for the given potentially nested global location.
fn get_parents_of_global(
    location: &AbstractLocation,
    generic_pointer_size: ByteSize,
) -> Vec<AbstractLocation> {
    if let AbstractLocation::GlobalPointer(_, _) = location {
        let (parent, _offset) = location.get_parent_location(generic_pointer_size).unwrap();
        let mut parents = get_parents_of_global(&parent, generic_pointer_size);
        parents.push(parent);
        parents
    } else {
        Vec::new()
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
pub fn propagate_globals(
    project: &Project,
    fn_sigs: &mut BTreeMap<Tid, FunctionSignature>,
    logs: &mut Vec<LogMessage>,
) {
    let known_globals = propagate_known_globals_top_down(project, fn_sigs);
    propagate_globals_bottom_up(project, &known_globals, fn_sigs, logs);
    // Also add parent locations of propagated globals to the function signatures
    add_parents_of_known_nested_globals(fn_sigs, project.get_pointer_bytesize());
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Mock the abstract location of a global parameter.
    fn mock_global(address: u64) -> AbstractLocation {
        AbstractLocation::GlobalAddress {
            address: address,
            size: ByteSize::new(4),
        }
    }

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
            .insert(mock_global(1000), AccessPattern::new().with_read_flag());
        let mut sig_callee1 = FunctionSignature::new();
        sig_callee1.global_parameters.insert(
            mock_global(2000),
            AccessPattern::new().with_dereference_flag(),
        );
        let mut sig_callee2 = FunctionSignature::new();
        sig_callee2
            .global_parameters
            .insert(mock_global(1000), AccessPattern::new_unknown_access());
        let mut fn_sigs = BTreeMap::from([
            (Tid::new("main"), sig_main),
            (Tid::new("callee1"), sig_callee1),
            (Tid::new("callee2"), sig_callee2),
        ]);

        // Propagate globals
        propagate_globals(&project, &mut fn_sigs, &mut Vec::new());
        // Check propagation results
        assert_eq!(
            &fn_sigs[&Tid::new("main")].global_parameters,
            &BTreeMap::from([(mock_global(1000), AccessPattern::new_unknown_access())])
        );
        assert_eq!(
            &fn_sigs[&Tid::new("callee1")].global_parameters,
            &BTreeMap::from([
                (mock_global(1000), AccessPattern::new_unknown_access()),
                (
                    mock_global(2000),
                    AccessPattern::new().with_dereference_flag()
                )
            ])
        );
        assert_eq!(
            &fn_sigs[&Tid::new("callee2")].global_parameters,
            &BTreeMap::from([(mock_global(1000), AccessPattern::new_unknown_access())])
        );
    }

    #[test]
    fn test_add_parent_locations() {
        // The case of a known nested global parameter without knowing the parent locations happens
        // when a callee returns a nested global in a return register.
        let location = AbstractLocation::mock_global(0x2000, &[8, 16], 8);
        let globals = BTreeMap::from([(location, AccessPattern::new_unknown_access())]);
        let fn_sig = FunctionSignature {
            parameters: BTreeMap::new(),
            global_parameters: globals,
        };
        let mut fn_sigs = BTreeMap::from([(Tid::new("func"), fn_sig)]);
        add_parents_of_known_nested_globals(&mut fn_sigs, ByteSize::new(8));
        let fn_sig = &fn_sigs[&Tid::new("func")];
        let deref_pattern = AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag();
        assert_eq!(
            fn_sig.global_parameters,
            BTreeMap::from([
                (
                    AbstractLocation::mock_global(0x2000, &[8, 16], 8),
                    AccessPattern::new_unknown_access()
                ),
                (
                    AbstractLocation::mock_global(0x2000, &[8], 8),
                    deref_pattern
                ),
                (AbstractLocation::mock_global(0x2000, &[], 8), deref_pattern),
            ])
        );
    }
}
