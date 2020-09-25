use crate::bil::*;
use crate::intermediate_representation::Arg as IrArg;
use crate::intermediate_representation::Blk as IrBlk;
use crate::intermediate_representation::Def as IrDef;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::Jmp as IrJmp;
use crate::intermediate_representation::Program as IrProgram;
use crate::intermediate_representation::Project as IrProject;
use crate::intermediate_representation::Sub as IrSub;
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

    /// Add a suffix to the ID string and return the new `Tid`
    pub fn with_id_suffix(self, suffix: &str) -> Self {
        Tid {
            id: self.id + suffix,
            address: self.address,
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

impl Def {
    fn into_ir_defs(self) -> Vec<IrDef> {
        match self.rhs {
            Expression::Load { address, .. } => {
                let (defs, cleaned_address, _) = extract_loads_from_expression(*address, 0);
                let mut ir_defs: Vec<IrDef> = defs
                    .into_iter()
                    .map(|def| def.into_ir_assignment())
                    .collect();
                ir_defs.push(IrDef::Load {
                    address: cleaned_address.into(),
                    var: self.lhs.into(),
                });
                ir_defs
            }
            Expression::Store { address, value, .. } => {
                let (mut defs, cleaned_address, counter) =
                    extract_loads_from_expression(*address, 0);
                let (mut more_defs, cleaned_value, _) =
                    extract_loads_from_expression(*value, counter);
                defs.append(&mut more_defs);
                let mut ir_defs: Vec<IrDef> = defs
                    .into_iter()
                    .map(|def| def.into_ir_assignment())
                    .collect();
                ir_defs.push(IrDef::Store {
                    address: cleaned_address.into(),
                    value: cleaned_value.into(),
                });
                ir_defs
            }
            Expression::IfThenElse {
                condition,
                true_exp,
                false_exp,
            } => {
                // We only match for conditional stores.
                // Other usages of the `IfThenElse`-expression will result in panics.
                let (address, value) = match (*true_exp, *false_exp) {
                    (Expression::Store { address, value, .. }, Expression::Var(var))
                    | (Expression::Var(var), Expression::Store { address, value, .. })
                        if var == self.lhs =>
                    {
                        (address, value)
                    }
                    _ => panic!(),
                };
                let (mut defs, _cleaned_condition, counter) =
                    extract_loads_from_expression(*condition, 0);
                let (mut more_defs, cleaned_adress, counter) =
                    extract_loads_from_expression(*address, counter);
                let (mut even_more_defs, cleaned_value, _) =
                    extract_loads_from_expression(*value, counter);
                defs.append(&mut more_defs);
                defs.append(&mut even_more_defs);
                let mut ir_defs: Vec<IrDef> = defs
                    .into_iter()
                    .map(|def| def.into_ir_assignment())
                    .collect();
                ir_defs.push(IrDef::Store {
                    address: cleaned_adress.into(),
                    value: IrExpression::Unknown {
                        description: "BAP conditional store".into(),
                        size: cleaned_value.bitsize().into(),
                    },
                });
                ir_defs
            }
            _ => vec![self.into_ir_assignment()],
        }
    }

    fn into_ir_assignment(self) -> IrDef {
        IrDef::Assign {
            var: self.lhs.into(),
            value: self.rhs.into(),
        }
    }
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

impl From<Jmp> for IrJmp {
    fn from(jmp: Jmp) -> IrJmp {
        match jmp.kind {
            JmpKind::Goto(Label::Direct(tid)) => IrJmp::Branch(tid),
            JmpKind::Goto(Label::Indirect(expr)) => IrJmp::BranchInd(expr.into()),
            JmpKind::Return(Label::Indirect(expr)) => IrJmp::Return(expr.into()),
            JmpKind::Return(Label::Direct(_)) => panic!(),
            JmpKind::Call(call) => {
                let return_ = match call.return_ {
                    Some(Label::Direct(tid)) => Some(tid),
                    None => None,
                    _ => panic!(),
                };
                match call.target {
                    Label::Direct(tid) => IrJmp::Call {
                        target: tid,
                        return_,
                    },
                    Label::Indirect(expr) => IrJmp::CallInd {
                        target: expr.into(),
                        return_,
                    },
                }
            }
            JmpKind::Interrupt { value, return_addr } => IrJmp::CallOther {
                description: format!("Interrupt {}", value),
                return_: Some(return_addr),
            },
        }
    }
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

impl From<Blk> for IrBlk {
    fn from(blk: Blk) -> IrBlk {
        let mut ir_def_terms = Vec::new();
        for def_term in blk.defs {
            let ir_defs = def_term.term.into_ir_defs();
            assert!(!ir_defs.is_empty());
            if ir_defs.len() == 1 {
                ir_def_terms.push(Term {
                    tid: def_term.tid,
                    term: ir_defs.into_iter().next().unwrap(),
                });
            } else {
                for (counter, ir_def) in ir_defs.into_iter().enumerate() {
                    ir_def_terms.push(Term {
                        tid: Tid {
                            id: format!("{}_{}", def_term.tid.id, counter),
                            address: def_term.tid.address.clone(),
                        },
                        term: ir_def,
                    });
                }
            }
        }
        let ir_jmp_terms = blk
            .jmps
            .into_iter()
            .map(|jmp_term| Term {
                tid: jmp_term.tid,
                term: jmp_term.term.into(),
            })
            .collect();
        IrBlk {
            defs: ir_def_terms,
            jmps: ir_jmp_terms,
        }
    }
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
pub struct Program {
    pub subs: Vec<Term<Sub>>,
    pub extern_symbols: Vec<ExternSymbol>,
    pub entry_points: Vec<Tid>,
}

impl From<Program> for IrProgram {
    fn from(program: Program) -> IrProgram {
        let subs = program
            .subs
            .into_iter()
            .map(|sub_term| Term {
                tid: sub_term.tid,
                term: sub_term.term.into(),
            })
            .collect();
        IrProgram {
            subs,
            extern_symbols: program
                .extern_symbols
                .into_iter()
                .map(|symbol| symbol.into())
                .collect(),
            entry_points: program.entry_points,
        }
    }
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

impl From<Project> for IrProject {
    fn from(project: Project) -> IrProject {
        let program = Term {
            tid: project.program.tid,
            term: project.program.term.into(),
        };
        IrProject {
            program,
            cpu_architecture: project.cpu_architecture,
            stack_pointer_register: project.stack_pointer_register.into(),
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

impl From<Arg> for IrArg {
    fn from(arg: Arg) -> IrArg {
        match arg.location {
            Expression::Var(var) => IrArg::Register(var.into()),
            Expression::Load {
                address,
                size: bitsize,
                ..
            } => {
                let offset = match *address {
                    Expression::BinOp {
                        op: BinOpType::PLUS,
                        lhs,
                        rhs,
                    } => {
                        assert!(matches!(*lhs, Expression::Var(_)));
                        if let Expression::Const(bitvec) = *rhs {
                            bitvec.try_to_i64().unwrap()
                        } else {
                            panic!()
                        }
                    }
                    _ => panic!(),
                };
                IrArg::Stack {
                    offset,
                    size: bitsize.into(),
                }
            }
            _ => panic!(),
        }
    }
}

fn extract_loads_from_expression(expr: Expression, counter: u64) -> (Vec<Def>, Expression, u64) {
    use Expression::*;
    match expr {
        Load {
            memory,
            address,
            endian,
            size,
        } => {
            let (mut defs, cleaned_address, mut counter) =
                extract_loads_from_expression(*address, counter);
            counter += 1;
            let temp_var = Variable {
                name: format!("temp_{}", counter),
                type_: Type::Immediate(size),
                is_temp: true,
            };
            defs.push(Def {
                lhs: temp_var.clone(),
                rhs: Load {
                    memory,
                    address: Box::new(cleaned_address),
                    endian,
                    size,
                },
            });
            (defs, Var(temp_var), counter)
        }
        Var(_) | Const(_) | Unknown { .. } => (Vec::new(), expr, counter),
        Store { .. } | Let { .. } | IfThenElse { .. } => panic!(),
        BinOp { op, lhs, rhs } => {
            let (mut defs, cleaned_lhs, counter) = extract_loads_from_expression(*lhs, counter);
            let (mut defs_rhs, cleaned_rhs, counter) = extract_loads_from_expression(*rhs, counter);
            defs.append(&mut defs_rhs);
            (
                defs,
                BinOp {
                    op,
                    lhs: Box::new(cleaned_lhs),
                    rhs: Box::new(cleaned_rhs),
                },
                counter,
            )
        }
        UnOp { op, arg } => {
            let (defs, cleaned_arg, counter) = extract_loads_from_expression(*arg, counter);
            (
                defs,
                UnOp {
                    op,
                    arg: Box::new(cleaned_arg),
                },
                counter,
            )
        }
        Cast { kind, width, arg } => {
            let (defs, cleaned_arg, counter) = extract_loads_from_expression(*arg, counter);
            (
                defs,
                Cast {
                    kind,
                    width,
                    arg: Box::new(cleaned_arg),
                },
                counter,
            )
        }
        Extract {
            low_bit,
            high_bit,
            arg,
        } => {
            let (defs, cleaned_arg, counter) = extract_loads_from_expression(*arg, counter);
            (
                defs,
                Extract {
                    low_bit,
                    high_bit,
                    arg: Box::new(cleaned_arg),
                },
                counter,
            )
        }
        Concat { left, right } => {
            let (mut defs, cleaned_left, counter) = extract_loads_from_expression(*left, counter);
            let (mut defs_right, cleaned_right, counter) =
                extract_loads_from_expression(*right, counter);
            defs.append(&mut defs_right);
            (
                defs,
                Concat {
                    left: Box::new(cleaned_left),
                    right: Box::new(cleaned_right),
                },
                counter,
            )
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
