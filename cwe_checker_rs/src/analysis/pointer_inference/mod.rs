use crate::prelude::*;
use super::abstract_domain::*;
use crate::bil::{BitSize, Expression};
use crate::term::*;
use serde::{Deserialize, Serialize};
use super::graph::Graph;
use std::collections::BTreeMap;

mod data;
mod object;
mod identifier;
mod state;

use data::Data;
use object::AbstractObjectList;
use state::State;

pub fn run(program: Term<Program>) {
    println!("It works!");
    todo!()
}



struct Context<'a> {
    graph: Graph<'a>,
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
            Expression::Store{memory: _, address, value, endian: _, size} => {
                // TODO: At the moment, both memory and endianness are ignored. Change that!
                if let Ok(Data::Pointer(pointer)) = state.eval(address) {
                    let data = state.eval(value).unwrap_or(Data::new_top(*size));
                    let mut state = state.clone();
                    assert_eq!(data.bitsize(), *size);
                    for (target_id, target_offset) in pointer.iter_targets() {
                        state.memory.set_value(target_id.clone(), data.clone(), target_offset.clone());
                    }
                    return state;
                } else {
                    // TODO: Implement proper error handling here.
                    // Depending on the separation logic, the alternative to not changing the state would be to invaluate all knowledge about memory here.
                    return state.clone();
                }
            },
            expression => {
                let mut register = state.register.clone();
                // TODO: error messages while evaluating instructions are ignored at the moment.
                // These should be somehow made visible for the user or for debug purposes
                register.insert(def.term.lhs.name.clone(), state.eval(&expression).unwrap_or(Data::new_top(def.term.lhs.bitsize().unwrap())));
                State {
                    register,
                    memory: state.memory.clone()
                }
            },
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

    fn update_call(&self, value: &State, call: &Call) -> State {
        todo!()
    }

    fn update_return(
        &self,
        value: &State,
        value_before_call: Option<&State>,
    ) -> State {
        todo!()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        unimplemented!()
    }
}
