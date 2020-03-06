use crate::bil::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Tid(String);

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term<T> {
    tid: Tid,
    term: T,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Def {
    pub lhs: Variable,
    pub rhs: Expression,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Jmp {
    pub condition: Option<Expression>,
    pub kind: JmpKind,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum JmpKind {
    Call(Call),
    Goto(Label),
    Return(Label),
    Interrupt { value: isize, return_addr: Tid },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Call {
    pub target: Label,
    pub return_: Option<Label>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Label {
    Direct(Tid),
    Indirect(Expression),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    pub defs: Vec<Term<Def>>,
    pub jmps: Vec<Term<Jmp>>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    name: String,
    blocks: Vec<Term<Blk>>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Program {
    subs: Vec<Term<Sub>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_deserialization() {
        let string = "{\"term\":{\"defs\":[],\"jmps\":[]},\"tid\":\"@block\"}";
        let tid = Tid("@block".to_string());
        let block_term = Term {
            tid: tid,
            term: Blk {
                defs: Vec::new(),
                jmps: Vec::new(),
            }
        };
        assert_eq!(block_term,serde_json::from_str(&string).unwrap());
    }
}
