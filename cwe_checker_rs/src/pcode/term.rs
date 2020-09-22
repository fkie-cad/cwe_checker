use super::{Expression, Variable};
use crate::intermediate_representation::Blk as IrBlk;
use crate::intermediate_representation::Def as IrDef;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::Jmp as IrJmp;
use crate::intermediate_representation::Sub as IrSub;
use crate::prelude::*;
use crate::term::{Term, Tid};

// TODO: Handle the case where an indirect tail call is represented by CALLIND plus RETURN

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Call {
    pub target: Label,
    pub return_: Option<Label>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Jmp {
    pub mnemonic: JmpType,
    pub goto: Option<Label>,
    pub call: Option<Call>,
    pub condition: Option<Variable>,
}

// TODO: CALLOTHER is still missing!
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum JmpType {
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    RETURN,
}

impl From<Jmp> for IrJmp {
    fn from(jmp: Jmp) -> IrJmp {
        use JmpType::*;
        let unwrap_label_direct = |label| {
            if let Label::Direct(tid) = label {
                tid
            } else {
                panic!()
            }
        };
        let unwrap_label_indirect = |label| {
            if let Label::Indirect(expr) = label {
                expr
            } else {
                panic!()
            }
        };
        match jmp.mnemonic {
            BRANCH => IrJmp::Branch(unwrap_label_direct(jmp.goto.unwrap())),
            CBRANCH => IrJmp::CBranch {
                target: unwrap_label_direct(jmp.goto.unwrap()),
                condition: jmp.condition.unwrap().into(),
            },
            BRANCHIND => IrJmp::BranchInd(unwrap_label_indirect(jmp.goto.unwrap()).into()),
            CALL => {
                let call = jmp.call.unwrap();
                IrJmp::Call {
                    target: unwrap_label_direct(call.target),
                    return_: call.return_.map(unwrap_label_direct),
                }
            }
            CALLIND => {
                let call = jmp.call.unwrap();
                IrJmp::CallInd {
                    target: unwrap_label_indirect(call.target).into(),
                    return_: call.return_.map(unwrap_label_direct),
                }
            }
            RETURN => IrJmp::Return(unwrap_label_indirect(jmp.goto.unwrap()).into()),
        }
    }
}

// TODO: Remove since code duplication?
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Label {
    Direct(Tid),
    Indirect(Variable),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Def {
    pub lhs: Variable,
    pub rhs: Expression,
}

impl From<Def> for IrDef {
    fn from(def: Def) -> IrDef {
        use super::ExpressionType::*;
        match def.rhs.mnemonic {
            COPY => IrDef::Assign {
                var: def.lhs.into(),
                value: def.rhs.input0.unwrap().into(),
            },
            LOAD => IrDef::Load {
                var: def.lhs.into(),
                address: def.rhs.input1.unwrap().into(),
            },
            STORE => IrDef::Store {
                address: def.rhs.input1.unwrap().into(),
                value: def.rhs.input2.unwrap().into(),
            },
            PIECE | INT_EQUAL | INT_NOTEQUAL | INT_LESS | INT_SLESS | INT_LESSEQUAL
            | INT_SLESSEQUAL | INT_ADD | INT_SUB | INT_CARRY | INT_SCARRY | INT_SBORROW
            | INT_XOR | INT_AND | INT_OR | INT_LEFT | INT_RIGHT | INT_SRIGHT | INT_MULT
            | INT_DIV | INT_REM | INT_SDIV | INT_SREM | BOOL_XOR | BOOL_AND | BOOL_OR
            | FLOAT_EQUAL | FLOAT_NOTEQUAL | FLOAT_LESS | FLOAT_LESSEQUAL | FLOAT_ADD
            | FLOAT_SUB | FLOAT_MULT | FLOAT_DIV => IrDef::Assign {
                var: def.lhs.into(),
                value: IrExpression::BinOp {
                    op: def.rhs.mnemonic.into(),
                    lhs: Box::new(def.rhs.input0.unwrap().into()),
                    rhs: Box::new(def.rhs.input1.unwrap().into()),
                },
            },
            SUBPIECE => IrDef::Assign {
                var: def.lhs.clone().into(),
                value: IrExpression::Subpiece {
                    low_byte: def.rhs.input1.unwrap().into(),
                    size: def.lhs.size,
                    arg: Box::new(def.rhs.input0.unwrap().into()),
                },
            },
            INT_NEGATE | INT_2COMP | BOOL_NEGATE | FLOAT_NEGATE | FLOAT_ABS | FLOAT_SQRT
            | FLOAT_CEIL | FLOAT_FLOOR | FLOAT_ROUND | FLOAT_NAN => IrDef::Assign {
                var: def.lhs.into(),
                value: IrExpression::UnOp {
                    op: def.rhs.mnemonic.into(),
                    arg: Box::new(def.rhs.input0.unwrap().into()),
                },
            },
            INT_ZEXT | INT_SEXT | INT2FLOAT | FLOAT2FLOAT | TRUNC => IrDef::Assign {
                var: def.lhs.clone().into(),
                value: IrExpression::Cast {
                    op: def.rhs.mnemonic.into(),
                    size: def.lhs.size,
                    arg: Box::new(def.rhs.input0.unwrap().into()),
                },
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    pub defs: Vec<Term<Def>>,
    pub jmps: Vec<Term<Jmp>>,
}

impl From<Blk> for IrBlk {
    fn from(blk: Blk) -> IrBlk {
        let defs: Vec<Term<IrDef>> = blk
            .defs
            .into_iter()
            .map(|def_term| Term {
                tid: def_term.tid,
                term: def_term.term.into(),
            })
            .collect();
        let jmps: Vec<Term<IrJmp>> = blk
            .jmps
            .into_iter()
            .map(|jmp_term| Term {
                tid: jmp_term.tid,
                term: jmp_term.term.into(),
            })
            .collect();
        IrBlk { defs, jmps }
    }
}

// TODO: We need a unit test for stack parameter (that use location instead of var)!
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Arg {
    pub var: Option<Variable>,
    pub location: Option<Expression>,
    pub intent: ArgIntent,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum ArgIntent {
    INPUT,
    OUTPUT,
    BOTH,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    pub name: String,
    pub blocks: Vec<Term<Blk>>,
}

impl From<Sub> for IrSub {
    fn from(sub: Sub) -> IrSub {
        let blocks = sub
            .blocks
            .into_iter()
            .map(|block_term| Term {
                tid: block_term.tid,
                term: block_term.term.into(),
            })
            .collect();
        IrSub {
            name: sub.name,
            blocks,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    pub tid: Tid,
    pub address: String,
    pub name: String,
    pub calling_convention: Option<String>,
    pub arguments: Vec<Arg>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Program {
    pub subs: Vec<Term<Sub>>,
    pub extern_symbols: Vec<ExternSymbol>,
    pub entry_points: Vec<Tid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_deserialization() {
        let def: Def = serde_json::from_str(
            r#"
      {
        "lhs": {
          "name": "CF",
          "size": 1,
          "is_virtual": false
        },
        "rhs": {
          "mnemonic": "INT_CARRY",
          "input0": {
            "name": "RDX",
            "size": 8,
            "is_virtual": false
          },
          "input1": {
            "name": "RDI",
            "size": 8,
            "is_virtual": false
          }
        }
      }
      "#,
        )
        .unwrap();
        let _: IrDef = def.into();
    }

    #[test]
    fn label_deserialization() {
        let _: Label = serde_json::from_str(
            r#"
        {
            "Direct": {
              "id": "blk_00103901",
              "address": "00103901"
            }
        }
        "#,
        )
        .unwrap();
        let _: Label = serde_json::from_str(
            r#"
        {
            "Indirect": {
                "name": "00109ef0",
                "size": 8,
                "is_virtual": false
            }
        }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn jmp_deserialization() {
        let _: Term<Jmp> = serde_json::from_str(
            r#"
      {
        "tid": {
          "id": "instr_00102014_2",
          "address": "00102014"
        },
        "term": {
          "type_": "CALL",
          "mnemonic": "CALLIND",
          "call": {
            "target": {
              "Indirect": {
                  "name": "RAX",
                  "size": 8,
                  "is_virtual": false
              }
            },
            "return": {
              "direct": {
                "id": "blk_00102016",
                "address": "00102016"
              }
            }
          }
        }
      }
      "#,
        )
        .unwrap();
    }

    #[test]
    fn blk_deserialization() {
        let _: Term<Blk> = serde_json::from_str(
            r#"
    {
      "tid": {
        "id": "blk_00101000",
        "address": "00101000"
      },
      "term": {
        "defs": [],
        "jmps": []
      }
    }
    "#,
        )
        .unwrap();
    }

    #[test]
    fn arg_deserialization() {
        let _: Arg = serde_json::from_str(
            r#"
    {
      "var": {
        "name": "RDI",
        "size": 8,
        "is_virtual": false
      },
      "intent": "INPUT"
    }
    "#,
        )
        .unwrap();
    }

    #[test]
    fn sub_deserialization() {
        let _: Term<Sub> = serde_json::from_str(
            r#"
    {
      "tid": {
        "id": "sub_00101000",
        "address": "00101000"
      },
      "term": {
        "name": "sub_name",
        "blocks": []
      }
    }
    "#,
        )
        .unwrap();
    }

    #[test]
    fn extern_symbol_deserialization() {
        let _: ExternSymbol = serde_json::from_str(
            r#"
    {
      "tid": {
        "id": "sub_0010b020",
        "address": "0010b020"
      },
      "address": "0010b020",
      "name": "strncmp",
      "calling_convention": "__stdcall",
      "arguments": [
        {
          "var": {
            "name": "RDI",
            "size": 8,
            "is_virtual": false
          },
          "intent": "INPUT"
        },
        {
          "var": {
            "name": "RSI",
            "size": 8,
            "is_virtual": false
          },
          "intent": "INPUT"
        },
        {
          "var": {
            "name": "RDX",
            "size": 8,
            "is_virtual": false
          },
          "intent": "INPUT"
        },
        {
          "var": {
            "name": "EAX",
            "size": 4,
            "is_virtual": false
          },
          "intent": "OUTPUT"
        }
      ]
    }
    "#,
        )
        .unwrap();
    }

    #[test]
    fn program_deserialization() {
        let _: Term<Program> = serde_json::from_str(
            r#"
    {
      "tid": {
        "id": "prog_00101000",
        "address": "00101000"
      },
      "term": {
        "subs": [],
        "extern_symbols": [],
        "entry_points":[]
      }
    }
    "#,
        )
        .unwrap();
    }
}
