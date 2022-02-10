//! A fixpoint algorithm computing parameters of functions and their access patterns.
//!
//! The fixpoint algorithm tracks the values of registers and the stack,
//! although only stack accesses with known, constant offset are processed.
//! Accesses to potential function parameters are collected together with the type of the access
//! (is the value read, dereferenced for read access or dereferenced for write access).
//!
//! Known limitations of the analysis:
//! * The analysis is an overapproximation in the sense that it may generate more input parameters
//!   than actually exist in some cases.
//! * Only registers that are potential parameter registers in the standard calling convention
//!   of the CPU architecture are considered as potential parameter registers.
//!   For functions that use other registers
//!   than those in the standard calling convention for parameter passing
//!   the results of this analysis will be wrong.
//! * Parameters that are used as input values for variadic functions (e.g. sprintf) may be missed
//!   since detection of variadic function parameters is not yet implemented for this analysis.
//! * If only a part (e.g. a single byte) of a stack parameter is accessed instead of the whole parameter
//!   then a duplicate stack parameter may be generated.
//!   A proper sanitation for this case is not yet implemented,
//!   although error messages are generated if such a case is detected.
//! * For floating point parameter registers the base register is detected as a parameter,
//!   although only a smaller sub-register is the actual parameter in many cases.
//!   Also, if a function uses sub-registers of floating point registers as local variables,
//!   the registers may be incorrectly flagged as input parameters.

use crate::abstract_domain::AbstractDomain;
use crate::analysis::fixpoint::Computation;
use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::forward_interprocedural_fixpoint::GeneralizedContext;
use crate::analysis::graph::*;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::BTreeMap;
use std::collections::HashMap;

mod context;
use context::*;
mod state;
use state::State;
mod access_pattern;
pub use access_pattern::AccessPattern;

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
                    computation.set_node_value(
                        node,
                        NodeValue::Value(State::new(
                            &sub.tid,
                            &project.stack_pointer_register,
                            project
                                .get_specific_calling_convention(&sub.term.calling_convention)
                                .unwrap(),
                        )),
                    )
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
/// and a list of log messages recorded during the computation of the signatures.
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
        if fn_sig.sanitize(project).is_err() {
            logs.push(
                LogMessage::new_error("Function parameters are not properly sanitized")
                    .location(fn_tid.clone())
                    .source("Function Signature Analysis"),
            );
        }
    }

    (fn_sig_map, logs)
}

/// The signature of a function.
/// Currently only contains information on the parameters of a function and their access patterns.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct FunctionSignature {
    /// The parameters of the function together with their access patterns.
    pub parameters: HashMap<Arg, AccessPattern>,
}

impl FunctionSignature {
    /// Generate an empty function signature.
    pub fn new() -> Self {
        Self {
            parameters: HashMap::new(),
        }
    }

    /// The returned number is the maximum of stack offset plus parameter size
    /// taken over all stack parameters in the function signature.
    pub fn get_stack_params_total_size(&self) -> i64 {
        let mut stack_params_total_size: i64 = 0;
        for param in self.parameters.keys() {
            if let Ok(param_offset) = param.eval_stack_offset() {
                let param_upper_bound =
                    param_offset.try_to_i64().unwrap() + (u64::from(param.bytesize()) as i64);
                stack_params_total_size = std::cmp::max(stack_params_total_size, param_upper_bound);
            }
        }
        stack_params_total_size
    }

    /// Merge the parameter list of `self` with the given parameter list.
    fn merge_parameter_list(&mut self, params: &[(Arg, AccessPattern)]) {
        for (arg, sig_new) in params {
            if let Some(sig_self) = self.parameters.get_mut(arg) {
                *sig_self = sig_self.merge(sig_new);
            } else {
                self.parameters.insert(arg.clone(), *sig_new);
            }
        }
    }

    /// Merge the function signature with the signature extracted from the given state.
    fn merge_with_fn_sig_of_state(&mut self, state: &State) {
        let params = state.get_params_of_current_function();
        self.merge_parameter_list(&params);
    }

    /// Sanitize the function signature:
    /// * Remove the return address from the list of stack parameters for x86-based architectures.
    /// * Check for unaligned stack parameters or stack parameters that are not pointer-sized
    ///   and return an error message if one is found.
    ///   This may indicate an error in the analysis
    ///   as no proper sanitation pass is implemented for such cases yet.
    fn sanitize(&mut self, project: &Project) -> Result<(), Error> {
        match project.cpu_architecture.as_str() {
            "x86" | "x86_32" | "x86_64" => {
                let return_addr_expr = Expression::Var(project.stack_pointer_register.clone());
                let return_addr_arg = Arg::Stack {
                    address: return_addr_expr,
                    size: project.stack_pointer_register.size,
                    data_type: None,
                };
                self.parameters.remove(&return_addr_arg);
            }
            _ => (),
        }
        self.check_for_unaligned_stack_params(&project.stack_pointer_register)
    }

    /// Return an error if an unaligned stack parameter
    /// or a stack parameter of different size than the generic pointer size is found.
    fn check_for_unaligned_stack_params(&self, stack_register: &Variable) -> Result<(), Error> {
        for arg in self.parameters.keys() {
            if let Arg::Stack { size, .. } = arg {
                if *size != stack_register.size {
                    return Err(anyhow!("Unexpected stack parameter size"));
                }
                if let Ok(offset) = arg.eval_stack_offset() {
                    if offset.try_to_u64()? % u64::from(stack_register.size) != 0 {
                        return Err(anyhow!("Unexpected stack parameter alignment"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for FunctionSignature {
    fn default() -> Self {
        Self::new()
    }
}
