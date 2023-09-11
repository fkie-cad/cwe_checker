//! This module implements a check for CWE-457: Use of Uninitialized Variable.
//!
//! Variables might not be initialized when they are used and this might lead to unexpected behavior.
//! This holds for allocated stack variables and variables returned by allocation function like `malloc`.
//! The use of such uninitialized variables might have security implications.
//!
//! The term variables and memory offsets are used here interchangeably.
//!
//! See <https://cwe.mitre.org/data/definitions/457.html> for detailed descriptions.
//!
//! ## How the check works
//!
//! Using an intraprocedural, top-down dataflow analysis
//! based on the results of the [Pointer Inference analysis](`crate::analysis::pointer_inference`).
//! The check keeps track of memory objects and their initialization status.
//! If an instruction is loading a memory offset, that is labeled as uninitialized the use of uninitialized variable is detected and a corresponding warning is triggered.
//! CWE warnings that differ, but share the same root cause are not deduplicated.
//!
//! ## False Positives
//!
//! - Since the analysis is not path-sensitive, infeasible paths may lead to false positives.
//! - Entirely uninitialized memory objects, that are passed as function parameter, trigger a warning without verifying its access.
//!
//!
//! ## False Negatives
//! - Only offset intervals that contain exact one value are considered for triggering warnings.
//! - External functions are not supported, except `malloc` and `memset`.

mod context;
use self::{context::Context, init_status::InitializationStatus, state::State};
use crate::{
    abstract_domain::{AbstractIdentifier, TryToBitvec},
    analysis::{
        self,
        fixpoint::Computation,
        forward_interprocedural_fixpoint::{
            create_computation, Context as generalContext, GeneralizedContext,
        },
        graph::Edge,
        pointer_inference::{PointerInference, State as PiState},
        vsa_results::VsaResult,
    },
    intermediate_representation::*,
};
use crate::{
    analysis::graph::*,
    utils::{
        log::{CweWarning, LogMessage},
        symbol_utils::find_symbol,
    },
    AnalysisResults, CweModule,
};
use analysis::interprocedural_fixpoint_generic::NodeValue::Value;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
mod init_status;
mod state;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE457",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct.
/// Lists all extern symbols in consideration, which create a memory object.
/// Lists all extern symbols, which should be ignored by this analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    allocation_symbols: Vec<String>,
    extern_symbol_whitelist: Vec<String>,
}

/// For the provided symbols return the corresponding `Tid` of and `NodeIndex` of the return site.
fn get_allocation_return_sites(
    symbols: Vec<String>,
    graph: &Graph,
    analysis_results: &AnalysisResults,
) -> Vec<(Tid, NodeIndex)> {
    let mut symbol_tids = vec![];
    for sym in symbols {
        if let Some((tid, _name)) = find_symbol(&analysis_results.project.program, &sym) {
            symbol_tids.push(tid);
        }
    }
    let mut return_nodes = vec![];
    for edge in graph.edge_indices() {
        if let Edge::ExternCallStub(jmp) = graph[edge] {
            if let Jmp::Call { target, .. } = &jmp.term {
                if symbol_tids.contains(&target) {
                    return_nodes.push((jmp.tid.clone(), graph.edge_endpoints(edge).unwrap().1));
                }
            }
        }
    }
    return_nodes
}

/// Resolves Tid of allocation function and the state of the return site to the
/// AbstractIdentifier of the new mem object.
fn get_abstract_identifier(tid: &Tid, state: &PiState) -> Option<AbstractIdentifier> {
    state
        .memory
        .get_all_object_ids()
        .into_iter()
        .find(|id| id.get_tid().address == tid.address)
}

/// Creates or updates a node's state by adding a heap object.
///
/// The state of nodes after allocation calls are extended by the newly created heap object and an uninitialized `MemRegion`.
fn init_heap_allocation<'a>(
    mut computation: Computation<GeneralizedContext<'a, Context<'a>>>,
    alloc_calls: &Vec<(Tid, NodeIndex)>,
    address_bytesize: ByteSize,
    pir: &PointerInference,
) -> Computation<GeneralizedContext<'a, Context<'a>>> {
    for (call, node) in alloc_calls {
        if let Some(fp_node_value) = pir.get_node_value(*node) {
            if let Some(id) = get_abstract_identifier(call, fp_node_value.unwrap_value()) {
                let mut state = State::new_with_id(id.clone(), address_bytesize);

                if let Some(node_value) = computation.get_node_value(*node) {
                    state
                        .tracked_objects
                        .extend(node_value.unwrap_value().tracked_objects.clone());
                }
                computation.set_node_value(*node, Value(state));
            }
        }
    }
    computation
}

/// Creates or updated every function's first node's state by adding the stackframe.
///
/// Note that, the offset `0` is set as `InitializationStatus::Init` and represents the return address.
fn init_stack_allocation<'a>(
    mut computation: Computation<GeneralizedContext<'a, Context<'a>>>,
    address_bytesize: ByteSize,
    pir: &PointerInference,
) -> Computation<GeneralizedContext<'a, Context<'a>>> {
    let graph = computation.get_graph().clone();

    for node in graph.node_indices() {
        if let Node::BlkStart(blk, sub) = graph[node] {
            if let Some(first_block) = sub.term.blocks.first() {
                if first_block == blk {
                    // blk is first block in sub
                    let stack_id = pir
                        .get_node_value(node)
                        .unwrap()
                        .unwrap_value()
                        .stack_id
                        .clone();

                    let mut state = State::new_with_id(stack_id.clone(), address_bytesize);
                    state.insert_single_offset(
                        &stack_id,
                        0,
                        InitializationStatus::Init {
                            addresses: [Tid::new("Return Address")].into(),
                        },
                    );

                    if let Some(node_value) = computation.get_node_value(node) {
                        state
                            .tracked_objects
                            .extend(node_value.unwrap_value().tracked_objects.clone());
                    }
                    computation.set_node_value(node, Value(state));
                }
            }
        }
    }
    computation
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning_for_uninit_access_(
    location: &Tid,
    sub: &Sub,
    is_stack_allocation: bool,
    details: String,
) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "Access of uninitialized {} variable at 0x{} ({}) {}",
            match is_stack_allocation {
                true => "stack",
                false => "heap",
            },
            location.address,
            sub.name,
            details
        ),
    )
    .tids(vec![format!("{}", location)])
    .addresses(vec![location.address.clone()])
    .symbols(vec![])
}

/// Generate a CWE warning for a potentially detected instance of the CWE.
///
/// This warning contains the locations of potential initialization locations.
fn generate_cwe_warning_for_maybe_uninit_access(
    location: &Tid,
    sub: &Sub,
    is_stack_allocation: bool,
    maybe_uninit_locations: HashMap<i64, HashSet<Tid>>,
    details: String,
) -> CweWarning {
    let mut description = format!(
        "Access of potentially uninitialized {} variable at 0x{} ({}). {}\n",
        match is_stack_allocation {
            true => "stack",
            false => "heap",
        },
        location.address,
        sub.name,
        details
    );
    description.push_str("Offset\tPotential initialization location\n");
    for (offset, init_locations) in maybe_uninit_locations {
        description.push_str(
            format!(
                "{}\t{:?}\n",
                offset,
                init_locations
                    .into_iter()
                    .map(|x| x.address)
                    .collect::<Vec<String>>()
            )
            .as_str(),
        );
    }
    CweWarning::new(CWE_MODULE.name, CWE_MODULE.version, description)
        .tids(vec![format!("{}", location)])
        .addresses(vec![location.address.clone()])
        .symbols(vec![])
}

// Generates a warning according to a call with uninitialized parameter
fn generate_cwe_warning_for_uninit_parameter(
    location: &Tid,
    callee: &Sub,
    object_id: &AbstractIdentifier,
) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "Uninitialized memory object {} is passed to {} at {}",
            object_id, callee.name, location.address
        ),
    )
    .tids(vec![format!("{}", location)])
    .addresses(vec![location.address.clone()])
    .symbols(vec![callee.name.clone()])
}

/// Returns a CWE warning if the block contains a `Def:Load` of an uninitialized offset.
///
/// This function supports intra block initialization, thus `Def::Store` to uninitialized
/// offsets changes the state. The state is not assigned to the node afterwards.
fn find_uninit_access_in_blk<'a>(
    computation: &Computation<GeneralizedContext<'a, Context<'a>>>,
    value: &State,
    sub: &Sub,
    blk: &Blk,
) -> (Vec<CweWarning>, HashMap<String, String>) {
    let pir = computation.get_context().get_context().pir;
    let mut value = value.clone();
    let mut cwe_warnings = Vec::new();
    let mut warning_info: HashMap<String, String> = HashMap::new();

    for def in &blk.defs {
        if let Def::Load { .. } = &def.term {
            if let Some(data_domain) = pir.eval_address_at_def(&def.tid) {
                if let Some((source_id, offset_interval)) = data_domain.get_if_unique_target() {
                    if let Some(mem_region) = value.tracked_objects.get(source_id) {
                        if let Ok(offset) = offset_interval.try_to_offset() {
                            if source_id.to_string().contains("instr") {
                                // it is a heap object
                                if let InitializationStatus::Uninit =
                                    mem_region.get_init_status_at_byte_index(offset)
                                {
                                    cwe_warnings.push(generate_cwe_warning_for_uninit_access_(
                                        &def.tid,
                                        sub,
                                        false,
                                        "".to_string(),
                                    ));

                                    warning_info
                                        .insert(def.tid.to_string(), format!("offset: {}", offset));
                                } else if let InitializationStatus::MaybeInit { addresses } =
                                    mem_region.get_init_status_at_byte_index(offset)
                                {
                                    cwe_warnings.push(
                                        generate_cwe_warning_for_maybe_uninit_access(
                                            &def.tid,
                                            sub,
                                            false,
                                            HashMap::from([(offset, addresses)]),
                                            "".to_string(),
                                        ),
                                    );
                                    warning_info
                                        .insert(def.tid.to_string(), format!("offset: {}", offset));
                                }
                            } else {
                                // it is a stack frame
                                if let InitializationStatus::Uninit =
                                    mem_region.get_init_status_at_byte_index(offset)
                                {
                                    cwe_warnings.push(generate_cwe_warning_for_uninit_access_(
                                        &def.tid,
                                        sub,
                                        true,
                                        "".to_string(),
                                    ));

                                    warning_info
                                        .insert(def.tid.to_string(), format!("offset: {}", offset));
                                } else if let InitializationStatus::MaybeInit { addresses } =
                                    mem_region.get_init_status_at_byte_index(offset)
                                {
                                    cwe_warnings.push(
                                        generate_cwe_warning_for_maybe_uninit_access(
                                            &def.tid,
                                            sub,
                                            true,
                                            HashMap::from([(offset, addresses)]),
                                            "".to_string(),
                                        ),
                                    );
                                    warning_info
                                        .insert(def.tid.to_string(), format!("offset: {}", offset));
                                }
                            }
                        }
                    }
                }
            }
        }
        value = computation
            .get_context()
            .get_context()
            .update_def(&value, def)
            .unwrap();
    }

    cwe_warnings.dedup();
    (cwe_warnings, warning_info)
}

/// Checks if any parameter refers to an entirely uninitialized memory object and returns a warning if true.
fn is_call_with_uninit_parameter(
    arguments: &Vec<Arg>,
    call_tid: &Tid,
    pir: &PointerInference,
    state: &State,
    callee: &Sub,
) -> Option<CweWarning> {
    for arg in arguments {
        if let Some(parameter) = pir.eval_parameter_arg_at_call(call_tid, arg) {
            for id in parameter.get_relative_values().keys() {
                if state.object_is_uninitialized(id) {
                    return Some(generate_cwe_warning_for_uninit_parameter(
                        call_tid, callee, id,
                    ));
                }
            }
        }
    }
    None
}

/// Iterate the graph and sweeps for uninitialized access within blocks.
fn extract_results<'a>(
    computation: Computation<GeneralizedContext<'a, Context<'a>>>,
    extern_symbols_whitelist: Vec<String>,
) -> Vec<CweWarning> {
    let mut cwe_warnings = Vec::new();
    let mut warning_info = HashMap::new();
    let graph = computation.get_graph();
    let pir = computation.get_context().get_context().pir;
    for node in graph.node_indices() {
        if let Node::BlkStart(_, _) = graph[node] {
            if let Some(node_value) = computation.get_node_value(node) {
                let (mut warnings, info) = find_uninit_access_in_blk(
                    &computation,
                    node_value.unwrap_value(),
                    &graph[node].get_sub().term,
                    &computation.get_graph()[node].get_block().term,
                );

                cwe_warnings.append(&mut warnings);
                warning_info.extend(info);
            }
        }
    }

    for edge in graph.edge_indices() {
        // Iterating external calls, that are not white listed
        if let Edge::ExternCallStub(call) = graph[edge] {
            if let Jmp::Call { target, return_: _ } = &call.term {
                if let Some(ext_sym) = pir.get_context().extern_symbol_map.get(target) {
                    if !extern_symbols_whitelist.contains(&ext_sym.name) {
                        let node_index = graph.edge_endpoints(edge).unwrap().0;
                        if let Some(pir_state) = computation.get_node_value(node_index) {
                            let state = pir_state.unwrap_value();
                            let callee = graph[node_index].get_sub();

                            if let Some(warning) = is_call_with_uninit_parameter(
                                &ext_sym.parameters,
                                target,
                                pir,
                                state,
                                &callee.term,
                            ) {
                                cwe_warnings.push(warning);
                            }
                        }
                    }
                }
            }
        }
        // Iterating internal calls
        if let Edge::Call(call) = graph[edge] {
            if let Jmp::Call { target, return_: _ } = &call.term {
                let func_sig = computation.get_context().get_context().function_signatures;
                if let Some(signature) = func_sig.get(target) {
                    let arguments = &signature.parameters.keys().cloned().collect();
                    let node_index = graph.edge_endpoints(edge).unwrap().0;
                    if let Some(pir_state) = computation.get_node_value(node_index) {
                        let state = pir_state.unwrap_value();

                        if let Node::CallSource { source: _, target } = graph[node_index] {
                            let callee = &target.1.term;
                            if let Some(warning) = is_call_with_uninit_parameter(
                                arguments, &call.tid, pir, state, callee,
                            ) {
                                cwe_warnings.push(warning);
                            }
                        }
                    }
                }
            }
        }
    }
    cwe_warnings
}

pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let pointer_size = analysis_results.project.get_pointer_bytesize();
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let pir = analysis_results.pointer_inference.unwrap();

    let context = Context::new(analysis_results, config.extern_symbol_whitelist.clone());
    let allocation_target_nodes =
        get_allocation_return_sites(config.allocation_symbols, pir.get_graph(), analysis_results);

    let computation = create_computation(context, None);
    let computation = init_stack_allocation(computation, pointer_size, pir);
    let mut computation =
        init_heap_allocation(computation, &allocation_target_nodes, pointer_size, pir);

    computation.compute_with_max_steps(100);

    if !computation.has_stabilized() {
        panic!("Fixpoint for CWE 457 did not stabilize.");
    }

    let mut cwe_warnings = extract_results(computation, config.extern_symbol_whitelist);
    cwe_warnings.dedup();

    (vec![], cwe_warnings)
}
