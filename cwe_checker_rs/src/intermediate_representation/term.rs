use super::{ByteSize, Expression, Variable};
use crate::prelude::*;
use crate::term::{Term, Tid};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Def {
    Load {
        var: Variable,
        address: Expression,
    },
    Store {
        address: Expression,
        value: Expression,
    },
    Assign {
        var: Variable,
        value: Expression,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Jmp {
    Branch(Tid),
    BranchInd(Expression),
    CBranch {
        target: Tid,
        condition: Expression,
    },
    Call {
        target: Tid,
        return_: Option<Tid>,
    },
    CallInd {
        target: Expression,
        return_: Option<Tid>,
    },
    Return(Expression),
    CallOther {
        description: String,
        return_: Option<Tid>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    pub defs: Vec<Term<Def>>,
    pub jmps: Vec<Term<Jmp>>,
}
