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
use std::collections::HashSet;

mod context;
use context::*;
mod state;
use itertools::Itertools;
use state::State;
mod access_pattern;
pub use access_pattern::AccessPattern;
mod global_var_propagation;
use global_var_propagation::propagate_globals;
pub mod stubs;

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
                        .unwrap_or_else(|| {
                            project
                                .get_standard_calling_convention()
                                .expect("No standard calling convention found.")
                        });
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
        match fn_sig.sanitize(project) {
            Ok(merge_logs) => {
                for log in merge_logs {
                    logs.push(
                        LogMessage::new_info(log)
                            .location(fn_tid.clone())
                            .source("Function Signature Analysis"),
                    )
                }
            }
            Err(_) => logs.push(
                LogMessage::new_error("Function parameters are not properly sanitized")
                    .location(fn_tid.clone())
                    .source("Function Signature Analysis"),
            ),
        }
    }
    // Propagate globals in bottom-up direction in the call graph
    propagate_globals(project, &mut fn_sig_map);

    (fn_sig_map, logs)
}

/// The signature of a function.
/// Currently only contains information on the parameters of a function and their access patterns.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct FunctionSignature {
    /// The parameters of the function together with their access patterns.
    pub parameters: HashMap<Arg, AccessPattern>,
    /// Values in writeable global memory accessed by the function.
    /// Does not contain indirectly accessed values, e.g. values accessed by callees of this function.
    pub global_parameters: HashMap<u64, AccessPattern>,
}

impl FunctionSignature {
    /// Generate an empty function signature.
    pub fn new() -> Self {
        Self {
            parameters: HashMap::new(),
            global_parameters: HashMap::new(),
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

    /// Merge the parameter list and the global parameter list of `self` with the given lists.
    fn merge_parameter_lists(
        &mut self,
        params: &[(Arg, AccessPattern)],
        global_params: &[(u64, AccessPattern)],
    ) {
        for (arg, sig_new) in params {
            if let Some(sig_self) = self.parameters.get_mut(arg) {
                *sig_self = sig_self.merge(sig_new);
            } else {
                self.parameters.insert(arg.clone(), *sig_new);
            }
        }
        for (address, sig_new) in global_params {
            if let Some(sig_self) = self.global_parameters.get_mut(address) {
                *sig_self = sig_self.merge(sig_new);
            } else {
                self.global_parameters.insert(*address, *sig_new);
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
    ///   and return an error message if one is found.
    ///   This may indicate an error in the analysis
    ///   as no proper sanitation pass is implemented for such cases yet.
    fn sanitize(&mut self, project: &Project) -> Result<Vec<String>, Error> {
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
        self.check_for_unaligned_stack_params(&project.stack_pointer_register)?;
        self.merge_intersecting_stack_parameters()
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
    /// Merges two intersecting stack parameters by joining them one stack parameter.
    ///
    /// Two [Arg](intermediate_representation::Arg) are merged if *all* of the following applies:
    /// * parameters have the same `Datatype`
    /// * parameters return `Ok` on `Arg::eval_stack_offset()`
    /// * parameters intersect
    fn merge_intersecting_stack_parameters(&mut self) -> Result<Vec<String>, Error> {
        let mut merged_args = HashMap::new();
        let mut removed_args = HashSet::new();
        let mut logs = vec![];
        for ((first_arg, first_pattern), (second_arg, second_pattern)) in self
            .parameters
            .iter()
            .filter(|x| x.0.eval_stack_offset().is_ok())
            .sorted_by(|a, b| {
                match a
                    .0
                    .eval_stack_offset()
                    .unwrap()
                    .checked_sge(&b.0.eval_stack_offset().unwrap())
                    .unwrap()
                {
                    true => std::cmp::Ordering::Greater,
                    false => std::cmp::Ordering::Less,
                }
            })
            .tuple_windows()
        {
            if let Ok(((address, size), log)) =
                get_bounds_intersecting_stack_arg(first_arg, second_arg)
            {
                let merged_arg = Arg::Stack {
                    address,
                    size: ByteSize::from(size),
                    data_type: first_arg.get_data_type(),
                };
                merged_args.insert(merged_arg, first_pattern.merge(second_pattern));
                removed_args.insert(first_arg.clone());
                removed_args.insert(second_arg.clone());
                logs.extend(log.clone());
            }
        }
        for arg in removed_args {
            self.parameters.remove(&arg);
        }
        self.parameters.extend(merged_args);
        Ok(logs)
    }
}

/// Merges two stack parameters and returns address and size.
/// Also returns a message, if one argument is not a subset of the other one.
///
/// Returns `Err` if `first_arg` or `second_arg`:
/// * are not `Arg::Stack` types
/// * do not have the same `Datatype`
/// * return `Err` on `Arg::eval_stack_offset()`
/// * do not intersect
fn get_bounds_intersecting_stack_arg(
    first_arg: &Arg,
    second_arg: &Arg,
) -> Result<((Expression, u64), Vec<String>), Error> {
    if let (
        Arg::Stack {
            data_type: first_datatype,
            size: first_size,
            address: first_address,
        },
        Arg::Stack {
            data_type: second_datatype,
            size: second_size,
            ..
        },
    ) = (first_arg, second_arg)
    {
        let first_arg_offset = first_arg.eval_stack_offset()?.try_to_u64()?;
        let first_arg_size = u64::from(*first_size);
        let second_arg_offset = second_arg.eval_stack_offset()?.try_to_u64()?;
        let second_arg_size = u64::from(*second_size);

        if first_datatype == second_datatype {
            let mut logs = vec![];
            let first_arg_upper_bound = first_arg_offset + first_arg_size;
            // Check if they intersect
            if first_arg_upper_bound >= second_arg_offset {
                let second_arg_upper_bound = second_arg_offset + second_arg_size;
                // Check if subset
                if second_arg_upper_bound <= first_arg_upper_bound {
                } else {
                    // second arg is not a subset, but intersects
                    logs.push(
                        "Merged a stack parameter, that intersect another but is no subset"
                            .to_string(),
                    );
                }
                let merged_size = second_arg_upper_bound - first_arg_offset;
                return Ok(((first_address.clone(), merged_size), logs));
            } else {
                return Err(anyhow!("Args do not intersect"));
            }
        } else {
            return Err(anyhow!("Args do not share same datatype"));
        }
    }
    Err(anyhow!("Args are no stack arguments"))
}

impl Default for FunctionSignature {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{expr, variable};

    impl FunctionSignature {
        /// Create a mock x64 function signature with 2 parameters, one of which is accessed mutably,
        /// one mutably accessed global variable at address 0x2000
        /// and one immutably accessed global variable at address 0x3000.
        pub fn mock_x64() -> FunctionSignature {
            let mut write_access_pattern = AccessPattern::new();
            write_access_pattern.set_unknown_access_flags();
            let parameters = HashMap::from_iter([
                (
                    Arg::from_var(variable!("RDI:8"), None),
                    AccessPattern::new(),
                ),
                (
                    Arg::from_var(variable!("RSI:8"), None),
                    write_access_pattern,
                ),
            ]);
            FunctionSignature {
                parameters,
                global_parameters: HashMap::from([
                    (0x2000, AccessPattern::new_unknown_access()),
                    (0x3000, AccessPattern::new().with_dereference_flag()),
                ]),
            }
        }
    }

    #[test]
    fn test_parameter_merging() {
        let mut func_sig = FunctionSignature::mock_x64();
        let stack_parm_1 = Arg::Stack {
            address: expr!("RSP:8 + 0x1000:8"),
            size: 8.into(),
            data_type: Some(Datatype::Integer),
        };
        let stack_parm_2 = Arg::Stack {
            address: expr!("RSP:8 + 0x1004:8"),
            size: 8.into(),
            data_type: Some(Datatype::Integer),
        };
        func_sig
            .parameters
            .insert(stack_parm_1, AccessPattern::new());
        func_sig
            .parameters
            .insert(stack_parm_2, AccessPattern::new());

        assert_eq!(
            func_sig.merge_intersecting_stack_parameters().unwrap(),
            vec!["Merged a stack parameter, that intersect another but is no subset"]
        );
        let mut expected_function_sig = FunctionSignature::mock_x64();
        let expected_stack_arg = Arg::Stack {
            address: expr!("RSP:8 + 0x1000:8"),
            size: 12.into(),
            data_type: Some(Datatype::Integer),
        };
        expected_function_sig
            .parameters
            .insert(expected_stack_arg, AccessPattern::new());
        assert_eq!(func_sig, expected_function_sig);
    }
}
