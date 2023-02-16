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
use crate::abstract_domain::Interval;
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
        self.merge_overlapping_stack_parameters()
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

    fn merge_overlapping_stack_parameters(&mut self) -> Result<Vec<String>, Error> {
        let mut merged_args = HashMap::new();
        let mut removed_args = HashSet::new();
        let mut logs = vec![];
        for ((arg, pattern), (other_arg, other_pattern)) in
            self.parameters.iter().combinations(2).map(|v| (v[0], v[1]))
        {
            if let Ok((merged_interval, log)) = merge_overlapping_stack_arg(arg, other_arg) {
                let merged_arg = Arg::Stack {
                    address: Expression::Const(merged_interval.start.clone()),
                    size: ByteSize::from(
                        merged_interval
                            .end
                            .bin_op(BinOpType::IntSub, &merged_interval.start)?
                            .try_to_u64()?,
                    ),
                    data_type: arg.get_data_type(),
                };
                merged_args.insert(merged_arg, pattern.merge(other_pattern));
                removed_args.insert(arg.clone());
                removed_args.insert(other_arg.clone());
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

/// Returns the merged offset interval of two stack arguments
///
/// Returns `Err` if `self` or `stack_arg`:
/// * are not `Arg::Stack`
/// * do not have the same `Datatype`
/// * return `Err` on `Arg::eval_stack_offset()`
/// * do not intersect
pub fn merge_overlapping_stack_arg(
    arg: &Arg,
    stack_arg: &Arg,
) -> Result<(Interval, Vec<String>), Error> {
    if let (
        Arg::Stack {
            data_type: self_datatype,
            size: self_size,
            ..
        },
        Arg::Stack {
            data_type: other_datatype,
            size: other_size,
            ..
        },
    ) = (arg, stack_arg)
    {
        if self_datatype == other_datatype {
            let self_chunk = Interval::new(
                arg.eval_stack_offset()?,
                arg.eval_stack_offset()?
                    .bin_op(BinOpType::IntAdd, &Bitvector::from(u64::from(*self_size)))?,
                1,
            );
            let other_chunk = Interval::new(
                stack_arg.eval_stack_offset()?,
                stack_arg
                    .eval_stack_offset()?
                    .bin_op(BinOpType::IntAdd, &Bitvector::from(u64::from(*other_size)))?,
                1,
            );
            let mut logs = vec![];

            dbg!(&self_chunk, &other_chunk);
            // Check if the intervals intersect
            if self_chunk.signed_intersect(&other_chunk).is_ok() {
                // Check if they are not subsets
                if !((self_chunk.contains(&other_chunk.start)
                    && self_chunk.contains(&other_chunk.end))
                    || (other_chunk.contains(&self_chunk.start)
                        && other_chunk.contains(&self_chunk.end)))
                {
                    logs.push(format!("Merged stack parameters '{:?}' and '{:?}' intersected, but has not been a subset", arg.eval_stack_offset(), stack_arg.eval_stack_offset()))
                }

                return Ok((self_chunk.signed_merge(&other_chunk), logs));
            }
        } else {
            return Err(anyhow!("Args do not share same datatype"));
        }
    }
    Err(anyhow!("Args do not overlap"))
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
            address: expr!("0x1000:8"),
            size: 8.into(),
            data_type: Some(Datatype::Integer),
        };
        let stack_parm_2 = Arg::Stack {
            address: expr!("0x1004:8"),
            size: 8.into(),
            data_type: Some(Datatype::Integer),
        };
        func_sig
            .parameters
            .insert(stack_parm_1, AccessPattern::new());
        func_sig
            .parameters
            .insert(stack_parm_2, AccessPattern::new());

        assert_eq!(func_sig.merge_overlapping_stack_parameters().unwrap(),
        vec!["Merged stack parameters 'Ok(ApInt { len: BitWidth(64), digits: [Digit(4100)] })' and 'Ok(ApInt { len: BitWidth(64), digits: [Digit(4096)] })' intersected, but has not been a subset"]);
    }
}
