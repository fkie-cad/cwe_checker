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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    pub name: String,
    pub blocks: Vec<Term<Blk>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Arg {
    Register(Variable),
    Stack { offset: i64, size: ByteSize },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    pub tid: Tid,
    pub name: String,
    pub calling_convention: Option<String>,
    pub parameters: Vec<Arg>,
    pub return_values: Vec<Arg>,
    pub no_return: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Program {
    pub subs: Vec<Term<Sub>>,
    pub extern_symbols: Vec<ExternSymbol>,
    pub entry_points: Vec<Tid>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Project {
    pub program: Term<Program>,
    pub cpu_architecture: String,
    pub stack_pointer_register: Variable,
}
