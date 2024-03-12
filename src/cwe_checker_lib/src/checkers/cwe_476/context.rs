//! Context that defines the data flow analysis perfomed by this check.
//!
//! The check for CWE 476 is implemented as a taint analysis. Building on the
//! generic infrastructure in the [taint analysis module], this module defines
//! the concrete analysis that we use to detect potential NULL pointer
//! dereference bugs.
//!
//! [taint analysis module]: crate::analysis::taint

use super::CWE_MODULE;
use crate::analysis::graph::{Graph as Cfg, HasCfg, Node as CfgNode};
use crate::analysis::pointer_inference::{
    Data as PiData, PointerInference as PointerInferenceComputation,
};
use crate::analysis::taint::{state::State as TaState, TaintAnalysis};
use crate::analysis::vsa_results::{HasVsaResult, VsaResult};
use crate::intermediate_representation::*;
use crate::utils::log::CweWarning;

use std::collections::HashMap;
use std::convert::AsRef;
use std::sync::Arc;

/// The context object for the NULL-Pointer-Dereference check.
///
/// There is always only one source of taint for the analysis. On creation of a
/// `Context` object, the taint source is not set. Starting the fixpoint
/// algorithm without [setting the taint source](Context::set_taint_source())
/// first will lead to a panic. By resetting the taint source one can reuse the
/// context object for several fixpoint computations.
#[derive(Clone)]
pub struct Context<'a> {
    /// A pointer to the corresponding project struct.
    project: &'a Project,
    /// A pointer to the results of the pointer inference analysis.
    ///
    /// They are used to determine the targets of pointers to memory, which in
    /// turn is used to keep track of taint on the stack or on the heap.
    pi_result: &'a PointerInferenceComputation<'a>,
    /// Maps the TID of an extern symbol to the extern symbol struct.
    extern_symbol_map: Arc<HashMap<Tid, &'a ExternSymbol>>,
    /// The call whose return values are the sources for taint for the analysis.
    taint_source: Option<&'a Term<Jmp>>,
    /// The name of the function, whose return values are the taint sources.
    taint_source_name: Option<String>,
    /// The current subfunction.
    ///
    /// Since the analysis is intraprocedural, all nodes with state during the
    /// fixpoint algorithm should belong to this function.
    current_sub: Option<&'a Term<Sub>>,
    /// A channel where found CWE hits can be sent to.
    cwe_collector: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> HasCfg<'a> for Context<'a> {
    fn get_cfg(&self) -> &Cfg<'a> {
        self.pi_result.get_graph()
    }
}

impl<'a> HasVsaResult<PiData> for Context<'a> {
    fn vsa_result(&self) -> &impl VsaResult<ValueDomain = PiData> {
        self.pi_result
    }
}

impl<'a> AsRef<Project> for Context<'a> {
    fn as_ref(&self) -> &Project {
        self.project
    }
}

impl<'a> TaintAnalysis<'a> for Context<'a> {
    /// Generate a CWE warning if taint may be contained in the function parameters.
    ///
    /// If a possible parameter register of the call contains taint,
    /// generate a CWE warning and return `None` to suppress the generation of
    /// further warnings. Else just remove all taint contained in
    /// non-callee-saved registers.
    fn update_call_generic(
        &self,
        state: &TaState,
        call_tid: &Tid,
        calling_convention_hint: &Option<String>,
    ) -> Option<TaState> {
        if state.check_generic_function_params_for_taint(
            self.vsa_result(),
            call_tid,
            self.project,
            calling_convention_hint,
        ) {
            self.generate_cwe_warning(call_tid);

            None
        } else {
            let mut new_state = state.clone();

            if let Some(calling_conv) = self
                .project
                .get_specific_calling_convention(calling_convention_hint)
            {
                new_state.remove_non_callee_saved_taint(calling_conv);
            }

            Some(new_state)
        }
    }
    /// Generate a CWE warning if taint may be contained in the function parameters.
    ///
    /// Always returns `None` so that the analysis stays intraprocedural.
    fn update_call(
        &self,
        state: &TaState,
        call: &Term<Jmp>,
        _target: &CfgNode,
        calling_convention: &Option<String>,
    ) -> Option<TaState> {
        if state.check_generic_function_params_for_taint(
            self.vsa_result(),
            &call.tid,
            self.project,
            calling_convention,
        ) {
            self.generate_cwe_warning(&call.tid);
        }

        None
    }

    /// Generate a CWE warning if taint may be contained in the function parameters.
    ///
    /// If taint may be contained in the function parameters, generate a CWE
    /// warning and return `None` to the suppress the generation of
    /// further warnings. Else remove taint from non-callee-saved registers.
    fn update_call_stub(&self, state: &TaState, call: &Term<Jmp>) -> Option<TaState> {
        if state.is_empty() {
            return None;
        }

        match &call.term {
            Jmp::Call { target, .. } => {
                let extern_symbol = self
                    .extern_symbol_map
                    .get(target)
                    .expect("Extern symbol not found.");

                if state.check_extern_parameters_for_taint(
                    self.vsa_result(),
                    extern_symbol,
                    &call.tid,
                ) {
                    self.generate_cwe_warning(&call.tid);

                    None
                } else {
                    let mut new_state = state.clone();

                    new_state.remove_non_callee_saved_taint(
                        self.project.get_calling_convention(extern_symbol),
                    );

                    Some(new_state)
                }
            }
            Jmp::CallInd { .. } => self.update_call_generic(state, &call.tid, &None),
            _ => panic!("Malformed control flow graph encountered."),
        }
    }

    /// Stops taint propagation if jump depends on a tainted condition.
    ///
    /// We assume that any check that depends on tainted values is a NULL
    /// pointer check of the return value, and that the program handles both
    /// outcomes correctly.
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
        if state.is_empty() {
            // Without taint there is nothing to propagate.
            return None;
        }

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
            _ => Some(state.clone()),
        }
    }

    /// Generate a CWE warning if the subroutine may return taint.
    ///
    /// We assume that returning a tainted value means that the function may
    /// return a NULL pointer. This always generates a warning, even if this may
    /// be expected by the caller.
    fn update_return(
        &self,
        state: &TaState,
        _call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
        calling_convention: &Option<String>,
    ) {
        if state.check_return_values_for_taint(
            self.vsa_result(),
            &return_term.tid,
            self.project,
            calling_convention,
        ) {
            self.generate_cwe_warning(&return_term.tid);
        }
    }

    /// Generate a CWE warning if the Def was a load/store through a tainted pointer.
    ///
    /// If a warning is generated, return `None` to suppress the generation of
    /// further warnings. Else return the new state unchanged.
    fn update_def_post(
        &self,
        old_state: &TaState,
        new_state: TaState,
        def: &Term<Def>,
    ) -> Option<TaState> {
        if old_state.is_empty() {
            // Without taint there is nothing to propagate.
            return None;
        }

        match &def.term {
            Def::Load { var: _, address } if old_state.eval(address).is_tainted() => {
                self.generate_cwe_warning(&def.tid);
                None
            }
            Def::Store { address, .. } if old_state.eval(address).is_tainted() => {
                self.generate_cwe_warning(&def.tid);
                None
            }
            _ => Some(new_state),
        }
    }
}

impl<'a> Context<'a> {
    /// Create a new context object.
    ///
    /// Note that one has to set the taint source separately before starting the analysis!
    ///
    /// If one wants to run the analysis for several sources,
    /// one should clone or reuse an existing `Context` object instead of generating new ones,
    /// since this function can be expensive!
    pub fn new(
        project: &'a Project,
        pi_result: &'a PointerInferenceComputation<'a>,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        let mut extern_symbol_map = HashMap::new();
        for (tid, symbol) in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(tid.clone(), symbol);
        }
        Context {
            project,
            pi_result,
            extern_symbol_map: Arc::new(extern_symbol_map),
            taint_source: None,
            taint_source_name: None,
            current_sub: None,
            cwe_collector,
        }
    }

    /// Set the taint source and the current function for the analysis.
    pub fn set_taint_source(&mut self, taint_source: &'a Term<Jmp>, current_sub: &'a Term<Sub>) {
        let taint_source_name = match &taint_source.term {
            Jmp::Call { target, .. } => self
                .project
                .program
                .term
                .extern_symbols
                .get(target)
                .map(|symbol| symbol.name.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            _ => "Unknown".to_string(),
        };
        self.taint_source = Some(taint_source);
        self.taint_source_name = Some(taint_source_name);
        self.current_sub = Some(current_sub);
    }

    /// Generate a CWE warning for the taint source of the context object.
    fn generate_cwe_warning(&self, taint_access_location: &Tid) {
        let taint_source = self.taint_source.unwrap();
        let taint_source_name = self.taint_source_name.clone().unwrap();
        let cwe_warning = CweWarning::new(CWE_MODULE.name, CWE_MODULE.version,
            format!("(NULL Pointer Dereference) There is no check if the return value is NULL at {} ({}).",
            taint_source.tid.address, taint_source_name))
            .addresses(vec![taint_source.tid.address.clone(), taint_access_location.address.clone()])
            .tids(vec![format!("{}", taint_source.tid), format!("{taint_access_location}")])
            .symbols(vec![taint_source_name]);
        let _ = self.cwe_collector.send(cwe_warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::taint::Taint as TaTaint;
    use crate::{expr, variable};

    impl<'a> Context<'a> {
        pub fn mock(
            project: &'a Project,
            pi_results: &'a PointerInferenceComputation<'a>,
        ) -> Context<'a> {
            let (cwe_sender, _) = crossbeam_channel::unbounded();
            let mut context = Context::new(project, pi_results, cwe_sender);
            let taint_source = Box::new(Term {
                tid: Tid::new("taint_source"),
                term: Jmp::Call {
                    target: Tid::new("malloc"),
                    return_: None,
                },
            });
            let taint_source = Box::leak(taint_source);
            let current_sub = Box::new(Sub::mock("current_sub"));
            let current_sub = Box::leak(current_sub);

            context.set_taint_source(taint_source, current_sub);

            context
        }
    }

    #[test]
    fn update_call_generic() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let mut state = TaState::mock();

        // Test that taint is propagated through calls that do not receive
        // tainted arguments.
        assert!(context
            .update_call_generic(&state, &Tid::new("call_tid"), &None)
            .is_some());

        // Test that taint is not propagated through calls that receive tainted
        // arguments.
        state.set_register_taint(&variable!("RDX:8"), TaTaint::Tainted(ByteSize::new(8)));
        assert!(context
            .update_call_generic(&state, &Tid::new("call_tid"), &None)
            .is_none());
    }

    #[test]
    fn update_jump() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let (state, _pi_state) = TaState::mock_with_pi_state();

        // Test that no taint is propagated through conditions that depend on a
        // tainted value.
        let jump = Term {
            tid: Tid::new("jmp"),
            term: Jmp::CBranch {
                target: Tid::new("target"),
                condition: expr!("RAX:8"),
            },
        };
        assert!(<Context as TaintAnalysis>::update_jump(
            &context,
            &state,
            &jump,
            None,
            &Blk::mock()
        )
        .is_none());

        // Test that taint is propagated through conditions that do not depend
        // on a tainted value.
        let jump = Term {
            tid: Tid::new("jmp"),
            term: Jmp::CBranch {
                target: Tid::new("target"),
                condition: expr!("RBX:8"),
            },
        };
        assert!(<Context as TaintAnalysis>::update_jump(
            &context,
            &state,
            &jump,
            None,
            &Blk::mock()
        )
        .is_some());
    }
}
