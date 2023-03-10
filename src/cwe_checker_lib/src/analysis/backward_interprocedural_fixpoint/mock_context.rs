use super::*;
use crate::analysis::graph::Graph;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;

/// Identifier for BlkStart and BlkEnd nodes
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum StartEnd {
    Start,
    End,
}

/// A simple mock context, only containing the program cfg
#[derive(Clone)]
pub struct Context<'a> {
    pub graph: Graph<'a>,
    pub tid_to_node_index: HashMap<(Tid, Tid, StartEnd), NodeIndex>,
}

impl<'a> Context<'a> {
    pub fn new(project: &'a Project) -> Self {
        let mut graph = crate::analysis::graph::get_program_cfg(&project.program);
        graph.reverse();
        let mut tid_to_node_index: HashMap<(Tid, Tid, StartEnd), NodeIndex> = HashMap::new();
        for node in graph.node_indices() {
            let node_value = graph.node_weight(node).unwrap();
            match node_value {
                Node::BlkStart {
                    0: block,
                    1: subroutine,
                } => {
                    tid_to_node_index.insert(
                        (subroutine.tid.clone(), block.tid.clone(), StartEnd::Start),
                        node,
                    );
                }
                Node::BlkEnd {
                    0: block,
                    1: subroutine,
                } => {
                    tid_to_node_index.insert(
                        (subroutine.tid.clone(), block.tid.clone(), StartEnd::End),
                        node,
                    );
                }
                _ => (),
            }
        }
        Context {
            graph,
            tid_to_node_index,
        }
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
        let updated_value = *val + 1;
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
        Some(*value_after_jump)
    }

    /// Merge two values at the callsite if both exist
    /// If there is only one, simply copy it
    fn update_callsite(
        &self,
        target_value: Option<&u64>,
        return_value: Option<&u64>,
        _caller_sub: &Term<Sub>,
        _call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<u64> {
        match (target_value, return_value) {
            (Some(call), Some(fall)) => Some(self.merge(call, fall)),
            (Some(call), _) => Some(*call),
            (_, Some(fall)) => Some(*fall),
            _ => panic!("No values to merge at callsite!"),
        }
    }

    /// Simply copy the value
    fn split_call_stub(&self, combined_value: &u64) -> Option<u64> {
        Some(*combined_value)
    }

    /// Simply copy the value
    fn split_return_stub(
        &self,
        combined_value: &u64,
        _returned_from_sub: &Term<Sub>,
    ) -> Option<u64> {
        Some(*combined_value)
    }

    /// Simply copy the value
    fn update_call_stub(&self, value_after_call: &u64, _call: &Term<Jmp>) -> Option<u64> {
        Some(*value_after_call)
    }

    /// Simply copy the value
    fn specialize_conditional(
        &self,
        value_after_jump: &u64,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<u64> {
        Some(*value_after_jump)
    }
}
