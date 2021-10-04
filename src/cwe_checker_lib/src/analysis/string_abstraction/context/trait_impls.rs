use std::fmt::Debug;

use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop},
    analysis::string_abstraction::state::State,
    intermediate_representation::{Blk, Def, Expression, Jmp, Term},
};

use super::Context;

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug>
    crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a, T>
{
    type Value = State<T>;

    /// Get the underlying graph on which the analysis operates.
    fn get_graph(&self) -> &crate::analysis::graph::Graph<'a> {
        self.pointer_inference_results.get_graph()
    }

    /// Merge two state values.
    fn merge(&self, state1: &Self::Value, state2: &Self::Value) -> State<T> {
        state1.merge(state2)
    }

    fn update_def(&self, state: &State<T>, def: &Term<Def>) -> Option<State<T>> {
        let mut new_state = state.clone();
        if state.get_pointer_inference_state().is_none() {
            if self
                .block_first_def_set
                .contains(&(def.tid.clone(), state.get_current_sub().unwrap().tid))
            {
                if let Some(pi_state) = self.get_current_pointer_inference_state(state, &def.tid) {
                    new_state.set_pointer_inference_state(Some(pi_state));
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        self.update_pointer_inference_state(&mut new_state, def);
        match &def.term {
            Def::Assign {
                var: output,
                value: input,
            } => {
                new_state.handle_assign_and_load(
                    output,
                    input,
                    self.runtime_memory_image,
                    &self.block_first_def_set,
                    true,
                );
            }
            Def::Load {
                var: output,
                address: input,
            } => {
                new_state.handle_assign_and_load(
                    output,
                    input,
                    self.runtime_memory_image,
                    &self.block_first_def_set,
                    false,
                );
            }
            Def::Store { address, value } => new_state.handle_store(
                address,
                value,
                self.runtime_memory_image,
                &self.block_first_def_set,
            ),
        }

        Some(new_state)
    }

    fn update_jump(
        &self,
        state: &State<T>,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State<T>> {
        let mut new_state = state.clone();
        new_state.set_pointer_inference_state(None);
        Some(new_state)
    }

    fn update_call(
        &self,
        _state: &State<T>,
        _call: &Term<Jmp>,
        _target: &crate::analysis::graph::Node,
    ) -> Option<State<T>> {
        None
    }

    fn update_return(
        &self,
        _state: Option<&State<T>>,
        state_before_call: Option<&State<T>>,
        _call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
    ) -> Option<State<T>> {
        if let Some(state) = state_before_call {
            let mut new_state = state.clone();
            self.handle_unknown_symbol_calls(&mut new_state);
            new_state.set_pointer_inference_state(None);
            return Some(new_state);
        }

        None
    }

    fn update_call_stub(&self, state: &State<T>, call: &Term<Jmp>) -> Option<State<T>> {
        let mut new_state = state.clone();
        match &call.term {
            Jmp::Call { target, .. } => match self.extern_symbol_map.get(target) {
                Some(symbol) => {
                    if let Some(string_symbol) = self.string_symbol_map.get(target) {
                        new_state = self.handle_string_symbol_calls(string_symbol, &new_state);
                    } else {
                        new_state = self.handle_generic_symbol_calls(symbol, &new_state);
                    }
                }
                None => panic!("Extern symbol not found."),
            },
            Jmp::CallInd { .. } => self.handle_unknown_symbol_calls(&mut new_state),
            _ => panic!("Malformed control flow graph encountered."),
        }

        new_state.set_pointer_inference_state(None);
        Some(new_state)
    }

    fn specialize_conditional(
        &self,
        state: &State<T>,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<State<T>> {
        Some(state.clone())
    }
}

#[cfg(test)]
mod tests;
