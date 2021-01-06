use std::collections::HashSet;

use super::*;
use crate::analysis::graph::Graph;

/// A simple mock context, only containing the program cfg
#[derive(Clone)]
pub struct Context<'a> {
    pub graph: Graph<'a>,
}

impl<'a> Context<'a> {
    pub fn new(project: &'a Project) -> Self {
        let mut graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
        graph.reverse();
        Context { graph }
    }
}

impl<'a> crate::analysis::backward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = u64;

    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    /// Take the minimum of two values when merging
    fn merge(&self, val1: &u64, val2: &u64) -> u64 {
        std::cmp::min(*val1, *val2)
    }

    /// Increase the Def count when parsing one
    fn update_def(&self, val: &u64, _def: &Term<Def>) -> Option<u64> {
        let updated_value = val.clone() + 1;
        Some(updated_value)
    }

    /// Simply copy the value at the jumpsite
    fn update_jumpsite(
        &self,
        value_after_jump: &u64,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _jumpsite: &Term<Blk>,
    ) -> Option<u64> {
        Some(value_after_jump.clone())
    }

    /// Merge two values at the callsite if both exist
    /// If there is only one, simply copy it
    fn update_callsite(
        &self,
        value_after_call: Option<&u64>,
        fallthrough_value: Option<&u64>,
        _call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<u64> {
        match (value_after_call, fallthrough_value) {
            (Some(call), Some(fall)) => Some(self.merge(call, fall)),
            (Some(call), _) => Some(call.clone()),
            (_, Some(fall)) => Some(fall.clone()),
            _ => panic!("No values to merge at callsite!"),
        }
    }

    /// Simply copy the value
    fn split_call_stub(&self, combined_value: &u64) -> Option<u64> {
        Some(combined_value.clone())
    }

    /// Simply copy the value
    fn split_return_stub(&self, combined_value: &u64) -> Option<u64> {
        Some(combined_value.clone())
    }

    /// Simply copy the value
    fn update_call_stub(&self, value_after_call: &u64, _call: &Term<Jmp>) -> Option<u64> {
        Some(value_after_call.clone())
    }

    /// Simply copy the value
    fn specialize_conditional(
        &self,
        value_after_jump: &u64,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<u64> {
        Some(value_after_jump.clone())
    }
}
