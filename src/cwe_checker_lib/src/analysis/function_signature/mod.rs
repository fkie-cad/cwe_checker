//! A fixpoint algorithm computing parameters of functions and their access patterns.
//!
//! The fixpoint algorithm tracks the values of registers and the stack,
//! although only stack accesses with known, constant offset are processed.
//! Accesses to potential function parameters are collected together with the type of the access
//! (is the value read, dereferenced for read access or dereferenced for write access).
//! Accesses to constant addresses that may correspond to global variables are also tracked.
//!
//! Known limitations of the analysis:
//! * The analysis is an overapproximation in the sense that it may generate more input parameters
//!   than actually exist in some cases.
//! * Only registers that are potential parameter registers in the standard calling convention
//!   of the CPU architecture are considered as potential parameter registers.
//!   For functions that use other registers
//!   than those in the standard calling convention for parameter passing
//!   the results of this analysis will be wrong.
//! * Parameters that are used as input values for variadic functions may be missed.
//!   Some variadic functions are stubbed, i.e. parameter recognition should work for these.
//!   But not all variadic functions are stubbed.
//! * If only a part (e.g. a single byte) of a stack parameter is accessed instead of the whole parameter
//!   then a duplicate stack parameter may be generated.
//!   A proper sanitation for this case is not yet implemented,
//!   although error messages are generated if such a case is detected.
//! * For floating point parameter registers the base register is detected as a parameter,
//!   although only a smaller sub-register is the actual parameter in many cases.
//!   Also, if a function uses sub-registers of floating point registers as local variables,
//!   the registers may be incorrectly flagged as input parameters.

use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::AbstractLocation;
use crate::abstract_domain::AbstractMemoryLocation;
use crate::analysis::fixpoint::Computation;
use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::forward_interprocedural_fixpoint::GeneralizedContext;
use crate::analysis::graph::*;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::BTreeMap;

mod context;
use context::*;
mod state;
use state::State;
mod access_pattern;
pub use access_pattern::AccessPattern;
mod global_var_propagation;
use global_var_propagation::propagate_globals;
pub mod stubs;

/// The recursion depth limit for abstract locations to be tracked by the function signature analysis,
/// i.e. how many dereference operations an abstract location is allowed to contain
/// before the analysis stops tracking the location.
const POINTER_RECURSION_DEPTH_LIMIT: u64 = 3;

/// Generate the computation object for the fixpoint computation
/// and set the node values for all function entry nodes.
fn generate_fixpoint_computation<'a>(
    project: &'a Project,
    graph: &'a Graph,
) -> Computation<GeneralizedContext<'a, Context<'a>>> {
    let context = Context::new(project, graph);
    let mut computation = create_computation(context, None);
    // Set the node values for all function entry nodes.
    for node in graph.node_indices() {
        if let Node::BlkStart(block, sub) = graph[node] {
            if let Some(entry_block) = sub.term.blocks.get(0) {
                if entry_block.tid == block.tid {
                    // The node of a function entry point
                    let calling_convention = project
                        .get_specific_calling_convention(&sub.term.calling_convention)
                        .expect("No standard calling convention found.");
                    let mut fn_start_state = State::new(
                        &sub.tid,
                        &project.stack_pointer_register,
                        calling_convention,
                    );
                    if project.cpu_architecture.contains("MIPS") {
                        let _ = fn_start_state
                            .set_mips_link_register(&sub.tid, project.stack_pointer_register.size);
                    }
                    computation.set_node_value(node, NodeValue::Value(fn_start_state))
                }
            }
        }
    }
    computation
}

/// Extract the function signatures from the computed fixpoint.
///
/// This function needs to merge the signatures at all nodes corresponding to a function
/// to ensure that parameter accesses on non-returning execution paths of a function
/// are also recognized in the function signature.
fn extract_fn_signatures_from_fixpoint<'a>(
    project: &'a Project,
    graph: &'a Graph,
    fixpoint: Computation<GeneralizedContext<'a, Context<'a>>>,
) -> BTreeMap<Tid, FunctionSignature> {
    let mut fn_sig_map: BTreeMap<Tid, FunctionSignature> = project
        .program
        .term
        .subs
        .keys()
        .map(|tid| (tid.clone(), FunctionSignature::new()))
        .collect();
    for node in graph.node_indices() {
        match fixpoint.get_node_value(node) {
            None => (),
            Some(NodeValue::Value(state)) => {
                let fn_sig = fn_sig_map
                    .get_mut(state.get_current_function_tid())
                    .unwrap();
                fn_sig.merge_with_fn_sig_of_state(state);
            }
            Some(NodeValue::CallFlowCombinator {
                call_stub,
                interprocedural_flow,
            }) => {
                if let Some(state) = call_stub {
                    let fn_sig = fn_sig_map
                        .get_mut(state.get_current_function_tid())
                        .unwrap();
                    fn_sig.merge_with_fn_sig_of_state(state);
                }
                if let Some(state) = interprocedural_flow {
                    let fn_sig = fn_sig_map
                        .get_mut(state.get_current_function_tid())
                        .unwrap();
                    fn_sig.merge_with_fn_sig_of_state(state);
                }
            }
        }
    }
    fn_sig_map
}

/// Compute the function signatures for all functions in the project.
///
/// Returns a map from the function TIDs to their signatures,
/// and a list of log and debug messages recorded during the computation of the signatures.
///
/// For more information on the used algorithm see the module-level documentation.
pub fn compute_function_signatures<'a>(
    project: &'a Project,
    graph: &'a Graph,
) -> (BTreeMap<Tid, FunctionSignature>, Vec<LogMessage>) {
    let mut computation = generate_fixpoint_computation(project, graph);
    computation.compute_with_max_steps(100);
    let mut fn_sig_map = extract_fn_signatures_from_fixpoint(project, graph, computation);
    // Sanitize the parameters
    let mut logs = Vec::new();
    for (fn_tid, fn_sig) in fn_sig_map.iter_mut() {
        let info_log = fn_sig.sanitize(project);
        for log in info_log {
            logs.push(
                LogMessage::new_info(log)
                    .location(fn_tid.clone())
                    .source("Function Signature Analysis"),
            )
        }
    }
    // Propagate globals in bottom-up direction in the call graph
    propagate_globals(project, &mut fn_sig_map, &mut logs);

    (fn_sig_map, logs)
}

/// The signature of a function.
/// Currently only contains information on the parameters of a function and their access patterns.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct FunctionSignature {
    /// The parameters of the function together with their access patterns.
    pub parameters: BTreeMap<AbstractLocation, AccessPattern>,
    /// Values in writeable global memory accessed by the function.
    pub global_parameters: BTreeMap<AbstractLocation, AccessPattern>,
}

impl FunctionSignature {
    /// Generate an empty function signature.
    pub fn new() -> Self {
        Self {
            parameters: BTreeMap::new(),
            global_parameters: BTreeMap::new(),
        }
    }

    /// The returned number is the maximum of stack offset plus parameter size
    /// taken over all stack parameters in the function signature.
    pub fn get_stack_params_total_size(&self, stack_register: &Variable) -> i64 {
        let mut stack_params_total_size: i64 = 0;
        for param in self.parameters.keys() {
            if let AbstractLocation::Pointer(var, mem_location) = param {
                if var == stack_register {
                    match mem_location {
                        AbstractMemoryLocation::Location { offset, size } => {
                            stack_params_total_size = std::cmp::max(
                                stack_params_total_size,
                                offset + (u64::from(*size) as i64),
                            );
                        }
                        AbstractMemoryLocation::Pointer { offset, target: _ } => {
                            stack_params_total_size = std::cmp::max(
                                stack_params_total_size,
                                offset + (u64::from(stack_register.size) as i64),
                            );
                        }
                    }
                }
            }
        }
        stack_params_total_size
    }

    /// Merge the parameter list and the global parameter list of `self` with the given lists.
    fn merge_parameter_lists(
        &mut self,
        params: &[(&AbstractLocation, AccessPattern)],
        global_params: &[(&AbstractLocation, AccessPattern)],
    ) {
        for (arg, sig_new) in params {
            if let Some(sig_self) = self.parameters.get_mut(arg) {
                *sig_self = sig_self.merge(sig_new);
            } else {
                self.parameters.insert((*arg).clone(), *sig_new);
            }
        }
        for (address, sig_new) in global_params {
            if let Some(sig_self) = self.global_parameters.get_mut(address) {
                *sig_self = sig_self.merge(sig_new);
            } else {
                self.global_parameters.insert((*address).clone(), *sig_new);
            }
        }
    }

    /// Merge the function signature with the signature extracted from the given state.
    fn merge_with_fn_sig_of_state(&mut self, state: &State) {
        let params = state.get_params_of_current_function();
        let global_params = state.get_global_mem_params_of_current_function();
        self.merge_parameter_lists(&params, &global_params);
    }

    /// Sanitize the function signature:
    /// * Remove the return address from the list of stack parameters for x86-based architectures.
    /// * Check for unaligned stack parameters or stack parameters that are not pointer-sized
    ///   and return an info message if one is found.
    ///   This may indicate an error in the analysis
    ///   as no proper sanitation pass is implemented for such cases yet.
    /// * Merge intersecting stack parameters
    fn sanitize(&mut self, project: &Project) -> Vec<String> {
        match project.cpu_architecture.as_str() {
            "x86" | "x86_32" | "x86_64" => {
                let return_addr_location = AbstractLocation::from_stack_position(
                    &project.stack_pointer_register,
                    0,
                    project.get_pointer_bytesize(),
                );
                self.parameters.remove(&return_addr_location);
            }
            _ => (),
        }
        // FIXME: We check for intersecting stack parameter register, but not for intersecting nested parameters.
        // We should add a check for these to generate log messages (but probably without trying to merge such parameters)
        self.merge_intersecting_stack_parameters(&project.stack_pointer_register);
        self.check_for_unaligned_stack_params(&project.stack_pointer_register)
    }

    /// Return a log message for every unaligned stack parameter
    /// or a stack parameter of different size than the generic pointer size is found.
    fn check_for_unaligned_stack_params(&self, stack_register: &Variable) -> Vec<String> {
        let mut log_messages: Vec<String> = vec![];
        for param in self.parameters.keys() {
            if let Some(offset) = get_offset_if_simple_stack_param(param, stack_register) {
                if param.bytesize() != stack_register.size {
                    log_messages.push("Unexpected stack parameter size".into());
                }
                if offset % u64::from(stack_register.size) as i64 != 0 {
                    log_messages.push("Unexpected stack parameter alignment".into());
                }
            }
        }
        log_messages
    }

    /// Merges intersecting stack parameters by joining them into one stack parameter.
    ///
    /// Only non-nested stack parameters are joined by this function.
    fn merge_intersecting_stack_parameters(&mut self, stack_register: &Variable) {
        let stack_params: BTreeMap<(i64, ByteSize), (AbstractLocation, AccessPattern)> = self
            .parameters
            .iter()
            .filter_map(|(location, access_pattern)| {
                get_offset_if_simple_stack_param(location, stack_register).map(|offset| {
                    (
                        (offset, location.bytesize()),
                        (location.clone(), *access_pattern),
                    )
                })
            })
            .collect();

        let mut current_param: Option<(i64, i64, AccessPattern)> = None;
        for ((offset, _), (param, access_pattern)) in stack_params.into_iter() {
            self.parameters.remove(&param);
            if let Some((cur_offset, cur_size, cur_access_pattern)) = current_param {
                if offset < cur_offset + cur_size {
                    let merged_size = std::cmp::max(
                        cur_size,
                        offset - cur_offset + u64::from(param.bytesize()) as i64,
                    );
                    let merged_access_pattern = cur_access_pattern.merge(&access_pattern);
                    current_param = Some((cur_offset, merged_size, merged_access_pattern));
                } else {
                    self.parameters.insert(
                        generate_simple_stack_param(
                            cur_offset,
                            ByteSize::new(cur_size as u64),
                            stack_register,
                        ),
                        cur_access_pattern,
                    );
                    current_param =
                        Some((offset, u64::from(param.bytesize()) as i64, access_pattern));
                }
            } else {
                current_param = Some((offset, u64::from(param.bytesize()) as i64, access_pattern));
            }
        }
        if let Some((cur_offset, cur_size, cur_access_pattern)) = current_param {
            self.parameters.insert(
                generate_simple_stack_param(
                    cur_offset,
                    ByteSize::new(cur_size as u64),
                    stack_register,
                ),
                cur_access_pattern,
            );
        }
    }
}

impl Default for FunctionSignature {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionSignature {
    /// Generate a compact JSON-representation of the function signature for pretty printing.
    #[allow(dead_code)]
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut json_map = serde_json::Map::new();
        let mut param_map = serde_json::Map::new();
        for (param, pattern) in self.parameters.iter() {
            param_map.insert(
                format!("{param}"),
                serde_json::Value::String(format!("{pattern}")),
            );
        }
        json_map.insert(
            "Parameters".to_string(),
            serde_json::Value::Object(param_map),
        );
        let mut global_param_map = serde_json::Map::new();
        for (param, pattern) in self.global_parameters.iter() {
            global_param_map.insert(
                format!("{param}"),
                serde_json::Value::String(format!("{pattern}")),
            );
        }
        json_map.insert(
            "Globals".to_string(),
            serde_json::Value::Object(global_param_map),
        );
        serde_json::Value::Object(json_map)
    }
}

/// If the abstract location is a location on the stack
/// then return its offset relative to the zero position on the stack.
fn get_offset_if_simple_stack_param(
    param: &AbstractLocation,
    stack_register: &Variable,
) -> Option<i64> {
    if let AbstractLocation::Pointer(var, mem_location) = param {
        if var == stack_register {
            if let AbstractMemoryLocation::Location { offset, .. } = mem_location {
                return Some(*offset);
            }
        }
    }
    None
}

/// Generate an abstract location of a (non-nested) stack parameter.
fn generate_simple_stack_param(
    offset: i64,
    size: ByteSize,
    stack_register: &Variable,
) -> AbstractLocation {
    AbstractLocation::Pointer(
        stack_register.clone(),
        AbstractMemoryLocation::Location { offset, size },
    )
}

#[cfg(test)]
mod tests;
