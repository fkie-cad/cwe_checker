//! Definition of the Taint Analysis for CWE252.
//!
//! Implementation of the [`TaintAnalysis`] trait for this CWE check. See the
//! module documentation for more details on the algorithm and its limitations.

use super::MustUseCall;

use crate::analysis::fixpoint;
use crate::analysis::forward_interprocedural_fixpoint::{
    self, create_computation as fwd_fp_create_computation,
};
use crate::analysis::graph::{Graph as Cfg, HasCfg};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::analysis::pointer_inference::{Data as PiData, PointerInference};
use crate::analysis::taint::state::{MemoryTaint, RegisterTaint, State as TaState};
use crate::analysis::taint::TaintAnalysis;
use crate::analysis::vsa_results::{HasVsaResult, VsaResult};
use crate::intermediate_representation::{Blk, ExternSymbol, Jmp, Project, Term, Tid};
use crate::utils::debug::ToJsonCompact;
use crate::utils::log::CweWarning;

use std::convert::AsRef;

/// Type of the fixpoint computation of the taint analysis.
pub type FpComputation<'a, 'b> = fixpoint::Computation<
    forward_interprocedural_fixpoint::GeneralizedContext<'a, TaComputationContext<'a, 'b>>,
>;

impl ToJsonCompact for FpComputation<'_, '_> {
    fn to_json_compact(&self) -> serde_json::Value {
        let graph = self.get_graph();
        let mut json_nodes = serde_json::Map::new();

        for (node_index, node_value) in self.node_values().iter() {
            let node = graph.node_weight(*node_index).unwrap();

            if let NodeValue::Value(value) = node_value {
                json_nodes.insert(format!("{node}"), value.to_json_compact());
            }
        }

        serde_json::Value::Object(json_nodes)
    }
}

/// Type that represents the definition of the taint analysis.
///
/// Values of this type represent the taint analysis for a particular call to an
/// external function.
pub struct TaComputationContext<'a, 'b: 'a> {
    /// Extern function call that is analyzed.
    call: MustUseCall<'a>,
    project: &'a Project,
    pi_result: &'a PointerInference<'b>,
    /// Used to send generated CWE warnings to the collector.
    cwe_sender: crossbeam_channel::Sender<CweWarning>,
}

impl<'a, 'b: 'a> TaComputationContext<'a, 'b> {
    /// Creates a new taint analysis context for the given call to an external
    /// function.
    pub(super) fn new(
        call: MustUseCall<'a>,
        project: &'a Project,
        pi_result: &'a PointerInference<'b>,
        cwe_sender: &'a crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        Self {
            call,
            project,
            pi_result,
            cwe_sender: cwe_sender.clone(),
        }
    }

    /// Converts the taint analysis context into a fixpoint computation.
    ///
    /// The returned computation can be solved to analyze this particular
    /// function call.
    pub fn into_computation(self) -> FpComputation<'a, 'b> {
        let symbol = self.call.symbol;
        let vsa_result = self.vsa_result();
        let return_node = self.call.return_node;
        let node_value = NodeValue::Value(TaState::new_return(symbol, vsa_result, return_node));

        let mut computation = fwd_fp_create_computation(self, None);

        computation.set_node_value(return_node, node_value);

        computation
    }

    fn generate_cwe_warning(&self, warning_location: &Tid, reason: &str) {
        super::generate_cwe_warning(&self.cwe_sender, &self.call, warning_location, reason)
    }
}

impl<'a> HasCfg<'a> for TaComputationContext<'a, '_> {
    fn get_cfg(&self) -> &Cfg<'a> {
        self.pi_result.get_graph()
    }
}

impl HasVsaResult<PiData> for TaComputationContext<'_, '_> {
    fn vsa_result(&self) -> &impl VsaResult<ValueDomain = PiData> {
        self.pi_result
    }
}

impl AsRef<Project> for TaComputationContext<'_, '_> {
    fn as_ref(&self) -> &Project {
        self.project
    }
}

impl<'a> TaintAnalysis<'a> for TaComputationContext<'a, '_> {
    /// Generates a CWE warning when a transition function returns the empty
    /// state.
    ///
    /// If a transition function returns the empty state this implies that there
    /// is some time in the program where all information about the return value
    /// of a fallible call has been eradicated without a previous check.
    ///
    /// From this time onwards, the program cannot possibly know if the fallible
    /// operation has succeeded or not. This point is reported as a possible bug
    /// by the check.
    ///
    /// For an example where this rule is needed to detect an error consider the
    /// following program:
    ///
    /// ```c
    /// x = fallible_call();
    ///
    /// if (some_unrelated_condition) {
    ///   x = 42;
    /// }
    ///
    /// if (x < 0) {
    ///   return x;
    /// }
    ///
    /// // Do something that assumes that `fallible_call` has worked.
    /// ```
    ///
    /// A pure forward 'may' data flow analysis would only see a tainted `x`
    /// being used in a comparison and consider the fallible call to be checked.
    /// With this condition, the analysis would emit a warning for the term
    /// `x = 42` since at this point all information about the return value is
    /// lost.
    fn handle_empty_state_out(&self, tid: &Tid) -> Option<TaState> {
        self.generate_cwe_warning(tid, "empty_state");

        None
    }

    /// Update taint state on call to extern function.
    ///
    /// We almost always just want to remove the taint from non-callee-saved
    /// registers. However, for calls/jumps into nonreturning functions at the
    /// end of a procedure we need some logic to suppress false positives.
    fn update_extern_call(
        &self,
        state: &TaState,
        _call: &Term<Jmp>,
        project: &Project,
        extern_symbol: &ExternSymbol,
    ) -> Option<TaState> {
        // External symbols that are unconditional termination points. It does
        // not make sense to propagate taint through those so we always return
        // `None`.
        if extern_symbol.no_return {
            return None;
        }
        // External symbols that are effectively no-ops. Here we always return
        // the unmodified input state.
        //
        // FIXME: This is an artifact of the way in which we generate the CFG.
        // On x86 and amd64 kernel functions end in a 'jmp retpoline' but we
        // generate a 'call extern; return;', where we introduced an artificial
        // isolated return node. Another workaround would be to replace the jmp
        // with a ret in a normalization pass.
        const EXTERN_NOOP: [&str; 1] = ["__x86_return_thunk"];

        let mut new_state = state.clone();

        if !EXTERN_NOOP.iter().any(|s| s == &extern_symbol.name) {
            new_state.remove_non_callee_saved_taint(project.get_calling_convention(extern_symbol));
        }

        Some(new_state)
    }

    /// Stops taint propagation if jump depends on a tainted condition.
    ///
    /// We assume that any check that depends on tainted values is a check of
    /// the return value of the fallible function, and that the program handles
    /// all outcomes correctly.
    ///
    /// A jump can depend on a tainted condition in two ways, either it is
    /// executed because the condition evaluated to `true`, or because it
    /// evaluated to `false`, both cases must be handled here.
    fn update_jump(
        &self,
        state: &TaState,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<TaState> {
        // If this control flow transfer depends on a condition involving
        // a tainted value then we do not propagate any taint information to
        // the destination.
        match (&jump.term, untaken_conditional) {
            // Directly depends on a tainted value.
            (Jmp::CBranch { condition, .. }, _) if state.eval(condition).is_tainted() => None,
            // Branch is only taken because a condition based on a tainted value
            // evaluated to false.
            (
                _,
                Some(Term {
                    tid: _,
                    term: Jmp::CBranch { condition, .. },
                }),
            ) if state.eval(condition).is_tainted() => None,
            // Does not depend on tainted values.
            _ => {
                if state.is_empty() {
                    self.handle_empty_state_out(&jump.tid)
                } else {
                    Some(state.clone())
                }
            }
        }
    }

    /// Propagates taint from callee to caller.
    ///
    /// The check performs a bottom-up interprocedural taint analysis. The main
    /// idea is that: *If a function may propagate the return value of a
    /// fallible function call to its caller without checking it, then the
    /// function itself becomes "must check".* (In the sense that the caller is
    /// now responsible for checking its return value.)
    ///
    /// The taint may be returned directly, indirectly by returning a pointer
    /// that can be used to reach taint, or written to global variables
    /// (possibly as a pointer).
    ///
    /// Limitations stem from two sources:
    ///
    /// - The calling convention may be unknown, which means we can not
    ///   determine precisely which taint will be reachable for the caller.
    ///
    /// See the source code comments for further information.
    ///
    /// Furthermore, this callback is responsible for detecting cases where
    /// taint may reach the end of a function without being returned.
    /// This implies that the called function may have ignored the return
    /// value of a fallible function call and there is no way for the caller to
    /// know the outcome. The check raises a warning in those cases.
    fn update_return_callee(
        &self,
        state: &TaState,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
        calling_convention: &Option<String>,
    ) -> Option<TaState> {
        let (register_taint, memory_taint) = state.clone().into_mem_reg_taint();

        // Only keep memory taint that will be propagated to the caller. We
        // compute this here since we want to notice when no taint is
        // propagated.
        let renaming_map = self.pi_result.get_call_renaming_map(&call_term.tid);
        let propagated_memory_taint: MemoryTaint = memory_taint
            .into_iter()
            .filter(|(aid, _)| {
                // This is still an over-approximation to the taint that will be
                // available to the caller since it might happen that all relative
                // values have non-exactly-known offsets.
                renaming_map.is_some_and(|renaming_map| {
                    renaming_map
                        .get(aid)
                        .is_some_and(|value| value.referenced_ids().next().is_some())
                })
            })
            .collect();

        let propagated_register_taint: RegisterTaint = if let Some(calling_convention) = self
            .project
            .get_specific_calling_convention(calling_convention)
        {
            let return_registers = calling_convention.get_all_return_register();

            // If there are tainted return registers we propagate the taint to
            // the caller, which makes them responsible for checking it.
            register_taint
                .into_iter()
                .filter(|(reg, taint)| return_registers.contains(&reg) && taint.is_tainted())
                .collect()
        } else {
            // We have tainted registers but we do not know the calling
            // convention. Here we simply return the complete register taint
            // of the callee to the caller. This heuristic should in practice
            // hopefully be a good approximation to the real calling convention:
            // - It is an over approximation so return registers will be
            //   propagated correctly.
            // - There is a chance that callee-saved registers have been
            //   overwritten with their saved values by the function epilog and
            //   are thus not tainted.
            // - There is a chance that caller saved registers will be restored
            //   by the caller such that the taint is immediatly eliminated and
            //   we catch cases where the called function has ignored tainted
            //   values.
            register_taint
        };

        let propagated_state =
            TaState::from_mem_reg_taint(propagated_register_taint, propagated_memory_taint);

        if propagated_state.is_empty() {
            // If we can not propagate any taint to the caller it is implied
            // that
            //
            // - the return value of a fallible function call may have been
            //   ignored by the callee
            // - AND the result is not returned to the caller
            //
            // Thus, callers of this function have no way to know if the
            // operation it performs was successful and the function itself
            // might not have checked it either.
            self.generate_cwe_warning(&return_term.tid, "return_no_taint");

            None
        } else {
            Some(propagated_state)
        }
    }
}
