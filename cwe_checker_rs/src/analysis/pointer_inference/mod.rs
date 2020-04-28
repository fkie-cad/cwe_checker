use super::abstract_domain::*;
use super::graph::Graph;
use crate::bil::{BitSize, Expression};
use crate::prelude::*;
use crate::term::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod data;
mod identifier;
mod object;
mod state;

use data::Data;
use identifier::*;
use object::AbstractObjectList;
use state::State;

pub fn run(program: Term<Program>) {
    println!("It works!");
    todo!()
}

struct Context<'a> {
    graph: Graph<'a>,
    project: &'a Project,
}

impl<'a> Context<'a> {
    pub fn new(program_term: &Term<Program>) -> Context {
        todo!()
    }
}

impl<'a> super::interprocedural_fixpoint::Problem<'a> for Context<'a> {
    type Value = State;

    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Self::Value {
        // TODO: handle loads in the right hand side expression for their side effects!
        match &def.term.rhs {
            Expression::Store {
                memory: _,
                address,
                value,
                endian: _,
                size,
            } => {
                // TODO: At the moment, both memory and endianness are ignored. Change that!
                if let Ok(Data::Pointer(pointer)) = state.eval(address) {
                    let data = state.eval(value).unwrap_or(Data::new_top(*size));
                    let mut state = state.clone();
                    assert_eq!(data.bitsize(), *size);
                    state.store_value(&Data::Pointer(pointer), &data);
                    return state;
                } else {
                    // TODO: Implement proper error handling here.
                    // Depending on the separation logic, the alternative to not changing the state would be to invaluate all knowledge about memory here.
                    return state.clone();
                }
            }
            expression => {
                let mut register = state.register.clone();
                // TODO: error messages while evaluating instructions are ignored at the moment.
                // These should be somehow made visible for the user or for debug purposes
                register.insert(
                    def.term.lhs.name.clone(),
                    state
                        .eval(&expression)
                        .unwrap_or(Data::new_top(def.term.lhs.bitsize().unwrap())),
                );
                State {
                    register,
                    ..state.clone()
                }
            }
        }
    }

    fn update_jump(
        &self,
        value: &State,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
    ) -> Option<State> {
        // TODO: Implement some real specialization of conditionals!
        Some(value.clone())
    }

    fn update_call(&self, state: &State, call_term: &Term<Jmp>, target_node: &super::graph::Node) -> State {
        let call = if let JmpKind::Call(ref call) = call_term.term.kind {
            call
        } else {
            panic!("Malformed control flow graph: Encountered call edge with a non-call jump term.")
        };
        let stack_offset_domain = self.get_current_stack_offset(state);

        if let Label::Direct(ref callee_tid) = call.target {
            let callee_stack_id = AbstractIdentifier::new(
                callee_tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let new_caller_stack_id = AbstractIdentifier::new(
                call_term.tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let stack_offset_adjustment = -stack_offset_domain.clone();
            let address_bitsize = self.project.stack_pointer_register.bitsize().unwrap();

            let mut callee_state = state.clone();
            // Replace the caller stack id with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id to avoid confusing caller and callee stack ids in case of recursive calls.
            callee_state.replace_abstract_id(
                &state.stack_id,
                &new_caller_stack_id,
                &stack_offset_adjustment,
            );
            // set the new stack_id
            callee_state.stack_id = new_caller_stack_id.clone();
            // add a new memory object for the callee stack frame
            callee_state.memory.add_abstract_object(
                callee_stack_id,
                Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap()).into(),
                object::ObjectType::Stack,
                address_bitsize,
            );
            // set the list of caller stack ids to only this caller id
            callee_state.caller_ids = BTreeSet::new();
            callee_state.caller_ids.insert(new_caller_stack_id.clone());
            // remove non-referenced objects from the state
            callee_state.remove_unreferenced_objects();

            return callee_state;
        } else {
            panic!("Indirect call edges not yet supported.")
            // TODO: Support indirect call edges!
        }
    }

    fn update_return(&self, state_before_return: &State, state_before_call: Option<&State>, call_term: &Term<Jmp>) -> Option<State> {
        // we only return to functions with a value before the call to prevent returning to dead code
        let state_before_call = match state_before_call {
            Some(value) => value,
            None => return None
        };
        let original_caller_stack_id = &state_before_call.stack_id;
        let caller_stack_id = AbstractIdentifier::new(
            call_term.tid.clone(),
            AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
        );
        let callee_stack_id = &state_before_return.stack_id;
        let stack_offset_on_call = self.get_current_stack_offset(state_before_call);

        let mut state_after_return = state_before_return.clone();
        state_after_return.replace_abstract_id(&caller_stack_id, original_caller_stack_id, &stack_offset_on_call);
        state_after_return.replace_abstract_id(callee_stack_id, original_caller_stack_id, &stack_offset_on_call); // TODO: check correctness with unit tests!
        state_after_return.stack_id = original_caller_stack_id.clone();
        state_after_return.caller_ids = state_before_call.caller_ids.clone();
        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();
        // TODO: Check that callee objects can actually be forgotten! If not, adjust handling of referenced objects in tracked memory.
        // Or alternatively try to merge abstract ids of untracked objects?

        // TODO: In theory all references to the callee stack frame are deleted, thus the callee stack frame gets deleted by remove_unreferenced_objects.
        // Check that!
        // Also, I need to detect and report cases where pointers to objects on the callee stack get returned, as this has its own CWE number!
        Some(state_after_return)
    }

    fn update_call_stub(&self, value: &State, call: &Call) -> Option<State> {
        todo!()
    }

    fn specialize_conditional(
        &self,
        value: &State,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<State> {
        // TODO: implement some real specialization of conditionals!
        Some(value.clone())
    }
}

impl<'a> Context<'a> {
    fn get_current_stack_offset(&self, state: &State) -> BitvectorDomain {
        if let Data::Pointer(ref stack_pointer) =
            state.register[&self.project.stack_pointer_register.name]
        {
            if stack_pointer.iter_targets().len() == 1 {
                // TODO: add sanity check that the stack id is the expected id
                let (_stack_id, stack_offset_domain) = stack_pointer.iter_targets().next().unwrap();
                stack_offset_domain.clone()
            } else {
                BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
            }
        } else {
            BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        unimplemented!()
    }
}
