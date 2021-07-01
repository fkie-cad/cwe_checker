use crate::{
    abstract_domain::{AbstractDomain, HasTop},
    analysis::string_abstraction::state::State,
    intermediate_representation::{Blk, Def, Expression, Jmp, Term},
};

use super::Context;

impl<'a, T: AbstractDomain + HasTop + Eq + From<String>>
    crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a, T>
{
    type Value = State<T>;

    /// Get the underlying graph on which the analysis operates.
    fn get_graph(&self) -> &crate::analysis::graph::Graph<'a> {
        &self.pointer_inference_results.get_graph()
    }

    /// Merge two state values.
    fn merge(&self, state1: &Self::Value, state2: &Self::Value) -> State<T> {
        state1.merge(state2)
    }

    fn update_def(&self, state: &State<T>, def: &Term<Def>) -> Option<State<T>> {
        let mut new_state = state.clone();
        self.update_pointer_inference_state(&mut new_state, def);
        match &def.term {
            Def::Assign {
                var: output,
                value: input,
            }
            | Def::Load {
                var: output,
                address: input,
                ..
            } => {
                new_state.handle_assign_and_load(def, input, output, self.runtime_memory_image);
            }
            Def::Store { address, value } => (),
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
        Some(state.clone())
    }

    fn update_call(
        &self,
        state: &State<T>,
        call: &Term<Jmp>,
        target: &crate::analysis::graph::Node,
    ) -> Option<State<T>> {
        todo!()
    }

    fn update_return(
        &self,
        state: Option<&State<T>>,
        state_before_call: Option<&State<T>>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
    ) -> Option<State<T>> {
        todo!()
    }

    fn update_call_stub(&self, state: &State<T>, call: &Term<Jmp>) -> Option<State<T>> {
        let mut new_state = state.clone();
        match &call.term {
            Jmp::Call { target, .. } => {
                let source_node = self.get_source_node(&state, &call.tid);
                if self.extern_symbol_map.get(target).is_some() {
                    if let Some(string_symbol) = self.string_symbol_map.get(target) {
                        new_state = self.handle_string_symbol_calls(
                            string_symbol,
                            &source_node,
                            &state,
                            &call.tid,
                        );
                    }
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            _ => panic!("Malformed control flow graph encountered."),
        }

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
