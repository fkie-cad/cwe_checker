use crate::bil::*;
use serde::{Deserialize, Serialize};

pub mod symbol;
use symbol::ExternSymbol;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct Tid {
    id: String,
    pub address: String,
}

impl Tid {
    pub fn new<T: ToString>(val: T) -> Tid {
        Tid {
            id: val.to_string(),
            address: "UNKNOWN".to_string(),
        }
    }
}

impl std::fmt::Display for Tid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term<T> {
    pub tid: Tid,
    pub term: T,
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
    pub jmps: Vec<Term<Jmp>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    pub name: String,
    pub blocks: Vec<Term<Blk>>,
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
    pub callee_saved_registers: Vec<String>,
    pub parameter_registers: Vec<String>,
}

impl Project {
    /// Get the bitsize of pointer values for the architecture of the project.
    pub fn get_pointer_bitsize(&self) -> BitSize {
        self.stack_pointer_register.bitsize().unwrap()
    }

    /// Substitute all let-binding-expressions in the project with equivalent expressions,
    /// that do not contain the let-bindings.
    /// This way subsequent analyses do not have to handle expressions containing let-bindings.
    pub fn replace_let_bindings(&mut self) {
        for sub in self.program.term.subs.iter_mut() {
            for blk in sub.term.blocks.iter_mut() {
                for def in blk.term.defs.iter_mut() {
                    def.term.rhs.replace_let_bindings();
                }
                for jmp in blk.term.jmps.iter_mut() {
                    if let Some(ref mut condition) = jmp.term.condition {
                        condition.replace_let_bindings();
                    }
                    match &mut jmp.term.kind {
                        JmpKind::Call(call) => {
                            call.target.replace_let_bindings();
                            if let Some(ref mut return_target) = call.return_ {
                                return_target.replace_let_bindings();
                            }
                        }
                        JmpKind::Goto(label) | JmpKind::Return(label) => {
                            label.replace_let_bindings()
                        }
                        JmpKind::Interrupt { .. } => (),
                    }
                }
            }
        }
    }
}

impl Label {
    /// Replace let-bindings inside the expression for `Indirect` labels.
    fn replace_let_bindings(&mut self) {
        if let Label::Indirect(expression) = self {
            expression.replace_let_bindings();
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Arg {
    pub var: Variable,
    pub location: Expression,
    pub intent: ArgIntent,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum ArgIntent {
    Input,
    Output,
    Both,
    Unknown,
}

impl ArgIntent {
    pub fn is_input(&self) -> bool {
        match self {
            Self::Input | Self::Both | Self::Unknown => true,
            Self::Output => false,
        }
    }

    pub fn is_output(&self) -> bool {
        match self {
            Self::Output | Self::Both | Self::Unknown => true,
            Self::Input => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_deserialization() {
        let string = "{\"term\":{\"defs\":[],\"jmps\":[]},\"tid\":{\"id\":\"@block\",\"address\":\"UNKNOWN\"}}";
        let tid = Tid::new("@block".to_string());
        let block_term = Term {
            tid,
            term: Blk {
                defs: Vec::new(),
                jmps: Vec::new(),
            },
        };
        println!("{}", serde_json::to_string(&block_term).unwrap());
        assert_eq!(block_term, serde_json::from_str(&string).unwrap());
    }
}
