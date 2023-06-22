use super::super::State;
use super::*;
use crate::analysis::graph::Graph;
use crate::checkers::cwe_119::stubs::ExternCallHandler;

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the control flow graph.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge two states.
    fn merge(&self, state1: &State, state2: &State) -> State {
        state1.merge(state2)
    }

    /// If the given [`Def`] is a load or store instruction, check whether it may access addresses
    /// that are out of bounds of the corresponding memory object.
    /// Generate CWE warnings accordingly.
    fn update_def(&self, state: &State, def: &Term<Def>) -> Option<State> {
        let mut state = state.clone();
        match &def.term {
            Def::Load { address: _, var } => {
                let address = match self.pointer_inference.eval_address_at_def(&def.tid) {
                    Some(address) => address,
                    None => return None, // There seems to be no pointer inference state here.
                };
                let warnings = state.check_address_access(&address, var.size, self);
                if !warnings.is_empty() {
                    let mut cwe_warning = CweWarning::new(
                        "CWE125",
                        super::super::CWE_MODULE.version,
                        format!(
                            "(Out-of-bounds Read) Memory read at {} may be out of bounds",
                            &def.tid.address
                        ),
                    );
                    cwe_warning.tids = vec![format!("{}", def.tid)];
                    cwe_warning.addresses = vec![def.tid.address.to_string()];
                    cwe_warning.other = vec![warnings];
                    self.log_collector.send(cwe_warning.into()).unwrap();
                }
            }
            Def::Store { address: _, value } => {
                let address = match self.pointer_inference.eval_address_at_def(&def.tid) {
                    Some(address) => address,
                    None => return None, // There seems to be no pointer inference state here.
                };
                let warnings = state.check_address_access(&address, value.bytesize(), self);
                if !warnings.is_empty() {
                    let mut cwe_warning = CweWarning::new(
                        "CWE787",
                        super::super::CWE_MODULE.version,
                        format!(
                            "(Out-of-bounds Write) Memory write at {} may be out of bounds.",
                            &def.tid.address
                        ),
                    );
                    cwe_warning.tids = vec![format!("{}", def.tid)];
                    cwe_warning.addresses = vec![def.tid.address.to_string()];
                    cwe_warning.other = vec![warnings];
                    self.log_collector.send(cwe_warning.into()).unwrap();
                }
            }
            Def::Assign { .. } => (),
        }

        Some(state)
    }

    /// The state does not change for intraprocedural jumps.
    fn update_jump(
        &self,
        state: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        Some(state.clone())
    }

    /// Always returns `None`, since the fixpoint computation is intraprocedural
    /// and the access to parameter values is checked in the callee separately.
    fn update_call(
        &self,
        _state: &State,
        _call: &Term<Jmp>,
        _target: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        // The analysis is intraprocedural and parameters are checked not here but in the callee.
        None
    }

    /// Just return the `state_before_call` since the fixpoint comutation is intraprocedural.
    fn update_return(
        &self,
        _state_before_return: Option<&State>,
        state_before_call: Option<&State>,
        _call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        // The analysis is intraprocedural
        state_before_call.cloned()
    }

    /// For calls to extern symbols check whether any parameter may point out of bounds of the corresponding memory object.
    /// Note that we do not know whether the called function accesses memory areas of certain sizes.
    /// Thus we only check that parameter pointers themselves point into the memory object
    /// but not whether certain address ranges around a pointer are still inside the corresponding memory object.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut state = state.clone();
        match &call.term {
            Jmp::Call { target, .. } => {
                if let Some(extern_symbol) = self.project.program.term.extern_symbols.get(target) {
                    let mut extern_call_handler =
                        ExternCallHandler::new(self, &mut state, extern_symbol, call);
                    extern_call_handler.handle_call();
                } else {
                    self.log_debug(
                        &call.tid,
                        "Call stub edge without associated extern symbol encountered.",
                    );
                }
            }
            Jmp::CallInd { .. } => {
                if let Some(cconv) = self.project.get_standard_calling_convention() {
                    for param in &cconv.integer_parameter_register {
                        let param_arg = Arg::from_var(param.clone(), None);
                        self.check_param_at_call(&mut state, &param_arg, &call.tid, None);
                    }
                }
            }
            _ => (),
        }
        Some(state)
    }

    /// Just return the given state without modification.
    fn specialize_conditional(
        &self,
        state: &State,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<State> {
        Some(state.clone())
    }
}
