use std::collections::HashMap;

use super::{Expression, ExpressionType, RegisterProperties, Variable};
use crate::intermediate_representation::Arg as IrArg;
use crate::intermediate_representation::Blk as IrBlk;
use crate::intermediate_representation::ByteSize;
use crate::intermediate_representation::CallingConvention as IrCallingConvention;
use crate::intermediate_representation::Def as IrDef;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::ExternSymbol as IrExternSymbol;
use crate::intermediate_representation::Jmp as IrJmp;
use crate::intermediate_representation::Program as IrProgram;
use crate::intermediate_representation::Project as IrProject;
use crate::intermediate_representation::Sub as IrSub;
use crate::prelude::*;

// TODO: Handle the case where an indirect tail call is represented by CALLIND plus RETURN

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Call {
    pub target: Option<Label>,
    #[serde(rename = "return")]
    pub return_: Option<Label>,
    pub call_string: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Jmp {
    pub mnemonic: JmpType,
    pub goto: Option<Label>,
    pub call: Option<Call>,
    pub condition: Option<Variable>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum JmpType {
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    CALLOTHER,
    RETURN,
}

impl From<Jmp> for IrJmp {
    /// Convert a P-Code jump to the internally used IR.
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
            BRANCHIND => {
                let target = unwrap_label_indirect(jmp.goto.unwrap());
                if let Some(address) = target.address {
                    // Sometimes there are entries in jump tables that have no associated symbol,
                    // i.e. jumping there means jumping to nowhere.
                    // Usually the jump ends up jumping to address 0.
                    IrJmp::CallOther {
                        description: format!(
                            "Unresolved jump: Jump to value read from address {}",
                            address
                        ),
                        return_: None,
                    }
                } else {
                    IrJmp::BranchInd(target.into())
                }
            }
            CALL => {
                let call = jmp.call.unwrap();
                IrJmp::Call {
                    target: unwrap_label_direct(call.target.unwrap()),
                    return_: call.return_.map(unwrap_label_direct),
                }
            }
            CALLIND => {
                let call = jmp.call.unwrap();
                IrJmp::CallInd {
                    target: unwrap_label_indirect(call.target.unwrap()).into(),
                    return_: call.return_.map(unwrap_label_direct),
                }
            }
            CALLOTHER => {
                let call = jmp.call.unwrap();
                IrJmp::CallOther {
                    description: call.call_string.unwrap(),
                    return_: call.return_.map(unwrap_label_direct),
                }
            }
            RETURN => IrJmp::Return(unwrap_label_indirect(jmp.goto.unwrap()).into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Label {
    Direct(Tid),
    Indirect(Variable),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Def {
    pub lhs: Option<Variable>,
    pub rhs: Expression,
}

impl From<Def> for IrDef {
    /// Convert a P-Code instruction to the internally used IR.
    fn from(def: Def) -> IrDef {
        use super::ExpressionType::*;
        match def.rhs.mnemonic {
            LOAD => IrDef::Load {
                var: def.lhs.unwrap().into(),
                address: def.rhs.input1.unwrap().into(),
            },
            STORE => IrDef::Store {
                address: def.rhs.input1.unwrap().into(),
                value: def.rhs.input2.unwrap().into(),
            },
            SUBPIECE => IrDef::Assign {
                var: def.lhs.clone().unwrap().into(),
                value: IrExpression::Subpiece {
                    low_byte: def.rhs.input1.unwrap().parse_to_bytesize(),
                    size: def.lhs.unwrap().size,
                    arg: Box::new(def.rhs.input0.unwrap().into()),
                },
            },
            INT_ZEXT | INT_SEXT | INT2FLOAT | FLOAT2FLOAT | TRUNC => IrDef::Assign {
                var: def.lhs.clone().unwrap().into(),
                value: IrExpression::Cast {
                    op: def.rhs.mnemonic.into(),
                    size: def.lhs.unwrap().size,
                    arg: Box::new(def.rhs.input0.unwrap().into()),
                },
            },
            _ => {
                let target_var = def.lhs.unwrap();
                if target_var.address.is_some() {
                    IrDef::Store {
                        address: IrExpression::Const(target_var.parse_to_bitvector()),
                        value: def.rhs.into(),
                    }
                } else {
                    IrDef::Assign {
                        var: target_var.into(),
                        value: def.rhs.into(),
                    }
                }
            }
        }
    }
}

impl Def {
    /// For `LOAD` instruction with address pointer size zero,
    /// correct the address size to the given pointer size.
    pub fn correct_pointer_sizes(&mut self, pointer_size: ByteSize) {
        if self.rhs.mnemonic == ExpressionType::LOAD {
            let input1 = self.rhs.input1.as_mut().unwrap();
            if input1.size == ByteSize::from(0 as u64) {
                input1.size = pointer_size;
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    pub defs: Vec<Term<Def>>,
    pub jmps: Vec<Term<Jmp>>,
}

impl From<Blk> for IrBlk {
    /// Convert a P-Code block to the internally used IR.
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

impl Blk {
    /// Add `LOAD` instructions for implicit memory accesses
    /// to convert them to explicit memory accesses.
    ///
    /// The generates `LOAD`s will have (incorrect) address sizes of zero,
    /// which must be corrected afterwards.
    fn add_load_defs_for_implicit_ram_access(&mut self) {
        let mut refactored_defs = Vec::new();
        for def in self.defs.iter() {
            let mut cleaned_def = def.clone();
            if let Some(input) = &def.term.rhs.input0 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp0");
                    cleaned_def.term.rhs.input0 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load0"),
                        term: load_def,
                    });
                }
            }
            if let Some(input) = &def.term.rhs.input1 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp1");
                    cleaned_def.term.rhs.input1 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load1"),
                        term: load_def,
                    });
                }
            }
            if let Some(input) = &def.term.rhs.input2 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp2");
                    cleaned_def.term.rhs.input2 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load2"),
                        term: load_def,
                    });
                }
            }
            refactored_defs.push(cleaned_def);
        }
        self.defs = refactored_defs;
    }
}

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
    pub addresses: Vec<String>,
    pub name: String,
    pub calling_convention: Option<String>,
    pub arguments: Vec<Arg>,
    pub no_return: bool,
}

impl From<ExternSymbol> for IrExternSymbol {
    /// Convert an extern symbol parsed from Ghidra to the internally used IR.
    fn from(symbol: ExternSymbol) -> IrExternSymbol {
        let mut parameters = Vec::new();
        let mut return_values = Vec::new();
        for arg in symbol.arguments {
            let ir_arg = if let Some(var) = arg.var {
                IrArg::Register(var.into())
            } else if let Some(expr) = arg.location {
                if expr.mnemonic == ExpressionType::LOAD {
                    IrArg::Stack {
                        offset: i64::from_str_radix(
                            expr.input0
                                .clone()
                                .unwrap()
                                .address
                                .unwrap()
                                .trim_start_matches("0x"),
                            16,
                        )
                        .unwrap(),
                        size: expr.input0.unwrap().size,
                    }
                } else {
                    panic!()
                }
            } else {
                panic!()
            };
            match arg.intent {
                ArgIntent::INPUT => parameters.push(ir_arg),
                ArgIntent::OUTPUT => return_values.push(ir_arg),
            }
        }
        IrExternSymbol {
            tid: symbol.tid,
            addresses: symbol.addresses,
            name: symbol.name,
            calling_convention: symbol.calling_convention,
            parameters,
            return_values,
            no_return: symbol.no_return,
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
    /// Convert a program parsed from Ghidra to the internally used IR.
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
pub struct CallingConvention {
    #[serde(rename = "calling_convention")]
    pub name: String,
    parameter_register: Vec<String>,
    return_register: Vec<String>,
    unaffected_register: Vec<String>,
    killed_by_call_register: Vec<String>,
}

impl From<CallingConvention> for IrCallingConvention {
    fn from(cconv: CallingConvention) -> IrCallingConvention {
        IrCallingConvention {
            name: cconv.name,
            parameter_register: cconv.parameter_register,
            return_register: cconv.return_register,
            callee_saved_register: cconv.unaffected_register,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Project {
    pub program: Term<Program>,
    pub cpu_architecture: String,
    pub stack_pointer_register: Variable,
    pub register_properties: Vec<RegisterProperties>,
    pub register_calling_convention: Vec<CallingConvention>,
}

impl From<Project> for IrProject {
    /// Convert a project parsed from Ghidra to the internally used IR.
    fn from(project: Project) -> IrProject {
        let mut program: Term<IrProgram> = Term {
            tid: project.program.tid,
            term: project.program.term.into(),
        };
        let register_map: HashMap<&String, &RegisterProperties> = project
            .register_properties
            .iter()
            .map(|p| (&p.register, p))
            .collect();
        let mut zero_extend_tids: HashMap<String, Tid> = HashMap::new();
        // iterates over definitions and checks whether sub registers are used
        // if so, they are swapped with subpieces of base registers
        for sub in program.term.subs.iter_mut() {
            for blk in sub.term.blocks.iter_mut() {
                let mut def_iter = blk.term.defs.iter_mut().peekable();
                while let Some(def) = def_iter.next() {
                    let peeked_def = def_iter.peek();
                    match &mut def.term {
                        IrDef::Assign { var, value } => {
                            let zero_tid: Option<Tid> = value.process_sub_registers_if_necessary(
                                Some(var),
                                &register_map,
                                peeked_def,
                            );
                            match zero_tid {
                                Some(tid) => {
                                    zero_extend_tids.insert(format!("{}", tid), tid);
                                }
                                _ => (),
                            }
                        }
                        IrDef::Load { var, address } => {
                            let zero_tid: Option<Tid> = address.process_sub_registers_if_necessary(
                                Some(var),
                                &register_map,
                                peeked_def,
                            );
                            match zero_tid {
                                Some(tid) => {
                                    zero_extend_tids.insert(format!("{}", tid), tid);
                                }
                                _ => (),
                            }
                        }
                        IrDef::Store { address, value } => {
                            address.process_sub_registers_if_necessary(
                                None,
                                &register_map,
                                peeked_def,
                            );
                            value.process_sub_registers_if_necessary(
                                None,
                                &register_map,
                                peeked_def,
                            );
                        }
                    }
                }
                let mut jmp_iter = blk.term.jmps.iter_mut();
                while let Some(jmp) = jmp_iter.next() {
                    match &mut jmp.term {
                        IrJmp::BranchInd(dest) => {
                            dest.process_sub_registers_if_necessary(None, &register_map, None);
                        }
                        IrJmp::CBranch { condition, .. } => {
                            condition.process_sub_registers_if_necessary(None, &register_map, None);
                        }
                        IrJmp::CallInd { target, .. } => {
                            target.process_sub_registers_if_necessary(None, &register_map, None);
                        }
                        IrJmp::Return(dest) => {
                            dest.process_sub_registers_if_necessary(None, &register_map, None);
                        }
                        _ => (),
                    }
                }
                // Remove all tagged zero extension instruction that came after a sub register instruction
                // since it has been wrapped around the former instruction.
                blk.term.defs.retain(|def| {
                    let def_tid = format!("{}", def.tid);
                    if zero_extend_tids.contains_key(&def_tid) {
                        return false;
                    }
                    true
                });
            }
        }
        IrProject {
            program,
            cpu_architecture: project.cpu_architecture,
            stack_pointer_register: project.stack_pointer_register.into(),
            calling_conventions: project
                .register_calling_convention
                .into_iter()
                .map(|cconv| cconv.into())
                .collect(),
        }
    }
}

impl Project {
    /// This function runs normalization passes to bring the project into a form
    /// that can be translated into the internally used intermediate representation.
    ///
    /// Currently implemented normalization passes:
    ///
    /// ### Insert explicit `LOAD` instructions for implicit memory loads in P-Code.
    ///
    /// Ghidra generates implicit loads for memory accesses, whose address is a constant.
    /// The pass converts them to explicit `LOAD` instructions.
    pub fn normalize(&mut self) {
        // Insert explicit `LOAD` instructions for implicit memory loads in P-Code.
        let generic_pointer_size = self.stack_pointer_register.size;
        for sub in self.program.term.subs.iter_mut() {
            for block in sub.term.blocks.iter_mut() {
                block.term.add_load_defs_for_implicit_ram_access();
                // The artificially created LOADs have pointers of size 0,
                // which we have to correct.
                for def in block.term.defs.iter_mut() {
                    def.term.correct_pointer_sizes(generic_pointer_size);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
