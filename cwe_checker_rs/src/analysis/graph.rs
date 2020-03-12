use petgraph::graph::DiGraph;
use serde::Serialize;
use crate::term::*;

pub type Graph<'a> = DiGraph<Node<'a>, Edge<'a>>;

#[derive(Serialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Node<'a> {
    BlkStart(&'a Term<Blk>),
    BlkEnd(&'a Term<Blk>),
    CallReturn(&'a Term<Blk>), // The block is the one from the call instruction
}

impl<'a> Node<'a> {
    pub fn get_block(&self) -> &Term<Blk> {
        use Node::*;
        match self {
            BlkStart(blk) | BlkEnd(blk) | CallReturn(blk) => blk,
        }
    }
}

// TODO: document that we assume that the graph only has blocks with either:
// - one unconditional call instruction
// - one return instruction
// - at most 2 intraprocedural jump instructions, i.e. at most one of them is a conditional jump
#[derive(Serialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Edge<'a> {
    Block,
    Jump(&'a Term<Jmp>, Option<&'a Term<Jmp>>),
    Call(&'a Call),
    ExternCallStub(&'a Call),
    CRCallStub,
    CRReturnStub,
    CRCombine,
}

#[derive(PartialEq, Eq)]
pub enum NodeValue<T: PartialEq + Eq> {
    Value(T),
    CallReturnCombinator { call: Option<T>, return_: Option<T> },
}

impl<T: PartialEq + Eq> NodeValue<T> {
    pub fn unwrap_value(&self) -> &T {
        match self {
            NodeValue::Value(value) => value,
            _ => panic!("Unexpected node value type"),
        }
    }
}


pub fn get_program_cfg(program: &Term<Program>) -> Graph {
    todo!()
}
