use super::abstract_domain::*;
use crate::bil::{BitSize, Expression};
use crate::term::*;
use serde::{Deserialize, Serialize};
use super::graph::Graph;
use std::collections::HashMap;

mod data;
mod object;

use data::Data;
use object::AbstractObjectList;

pub fn run(program: Term<Program>) {
    println!("It works!");
    todo!()
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
struct Value {
    register: HashMap<String, Data>,
    memory: AbstractObjectList,
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
    type Value = Value;

    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        todo!()
    }

    fn update_def(&self, value: &Self::Value, def: &Term<Def>) -> Self::Value {
        todo!()
    }

    fn update_jump(
        &self,
        value: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
    ) -> Option<Self::Value> {
        todo!()
    }

    fn update_call(&self, value: &Self::Value, call: &Call) -> Self::Value {
        todo!()
    }

    fn update_return(
        &self,
        value: &Self::Value,
        value_before_call: Option<&Self::Value>,
    ) -> Self::Value {
        todo!()
    }

    fn update_call_stub(&self, value: &Self::Value, call: &Call) -> Option<Self::Value> {
        todo!()
    }

    fn specialize_conditional(
        &self,
        value: &Self::Value,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<Self::Value> {
        // TODO: implement some real specialization of conditionals!
        Some(value.clone())
    }
}
