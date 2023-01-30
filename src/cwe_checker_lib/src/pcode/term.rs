use std::collections::{BTreeSet, HashMap};
use std::usize;

use super::subregister_substitution::replace_input_subregister;
use super::{Expression, ExpressionType, RegisterProperties, Variable};
use crate::intermediate_representation::Arg as IrArg;
use crate::intermediate_representation::Blk as IrBlk;
use crate::intermediate_representation::ByteSize;
use crate::intermediate_representation::CallingConvention as IrCallingConvention;
use crate::intermediate_representation::DatatypeProperties;
use crate::intermediate_representation::Def as IrDef;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::ExternSymbol as IrExternSymbol;
use crate::intermediate_representation::Jmp as IrJmp;
use crate::intermediate_representation::Program as IrProgram;
use crate::intermediate_representation::Project as IrProject;
use crate::intermediate_representation::RuntimeMemoryImage;
use crate::intermediate_representation::Sub as IrSub;
use crate::intermediate_representation::Variable as IrVariable;
use crate::prelude::*;
use crate::utils::log::LogMessage;

// TODO: Handle the case where an indirect tail call is represented by CALLIND plus RETURN

// TODO: Since we do not support BAP anymore, this module should be refactored
// to remove BAP-specific artifacts like the jump label type.

/// A call instruction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Call {
    /// The target label. May be `None` for `CALLOTHER` instructions.
    pub target: Option<Label>,
    /// The return label if the call is expected to return.
    #[serde(rename = "return")]
    pub return_: Option<Label>,
    /// A description of the instruction for `CALLOTHER` instructions.
    pub call_string: Option<String>,
}

/// A jump instruction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Jmp {
    /// The mnemonic of the jump.
    pub mnemonic: JmpType,
    /// The target label for intraprocedural jumps.
    pub goto: Option<Label>,
    /// The call struct for interprocedural jumps.
    pub call: Option<Call>,
    /// If the jump is a conditional jump,
    /// the varnode that has to evaluate to `true` for the jump to be taken.
    pub condition: Option<Variable>,
    /// A list of potential jump targets for indirect jumps.
    pub target_hints: Option<Vec<String>>,
}

/// A jump type mnemonic.
#[allow(missing_docs)]
#[allow(clippy::upper_case_acronyms)]
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
                IrJmp::BranchInd(target.into())
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

/// A jump label for distinguishing between direct and indirect jumps.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Label {
    /// The term identifier of the target of a direct jump.
    Direct(Tid),
    /// The varnode holding the target address of an indirect jump.
    Indirect(Variable),
}

/// An assignment instruction, assigning the result of an expression to a varnode.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Def {
    /// The target varnode whose value gets overwritten.
    pub lhs: Option<Variable>,
    /// The expression that determines the value to be written.
    pub rhs: Expression,
}

impl Def {
    /// Convert a P-Code instruction to the internally used IR.
    pub fn into_ir_def(self, generic_pointer_size: ByteSize) -> IrDef {
        use super::ExpressionType::*;
        match self.rhs.mnemonic {
            LOAD => {
                return IrDef::Load {
                    var: self.lhs.unwrap().into(),
                    address: self.rhs.input1.unwrap().into(),
                }
            }
            STORE => {
                return IrDef::Store {
                    address: self.rhs.input1.unwrap().into(),
                    value: self.rhs.input2.unwrap().into(),
                }
            }
            _ => (),
        }
        let target_var = self.lhs.unwrap();
        let value = match self.rhs.mnemonic {
            LOAD | STORE => unreachable!(),
            SUBPIECE => IrExpression::Subpiece {
                low_byte: self.rhs.input1.unwrap().parse_to_bytesize(),
                size: target_var.size,
                arg: Box::new(self.rhs.input0.unwrap().into()),
            },
            INT_ZEXT | INT_SEXT | INT2FLOAT | FLOAT2FLOAT | TRUNC | POPCOUNT => {
                IrExpression::Cast {
                    op: self.rhs.mnemonic.into(),
                    size: target_var.size,
                    arg: Box::new(self.rhs.input0.unwrap().into()),
                }
            }
            _ => self.rhs.into(),
        };
        if target_var.address.is_some() {
            IrDef::Store {
                address: IrExpression::Const(
                    target_var.parse_address_to_bitvector(generic_pointer_size),
                ),
                value,
            }
        } else {
            IrDef::Assign {
                var: target_var.into(),
                value,
            }
        }
    }
}

/// A basic block.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    /// The `Def` instructions of the block in chronological order.
    pub defs: Vec<Term<Def>>,
    /// The jump instructions at the end of the basic block.
    pub jmps: Vec<Term<Jmp>>,
}

impl Blk {
    /// Convert a P-Code block to the internally used IR.
    pub fn into_ir_blk(self, generic_pointer_size: ByteSize) -> IrBlk {
        let defs: Vec<Term<IrDef>> = self
            .defs
            .into_iter()
            .map(|def_term| Term {
                tid: def_term.tid,
                term: def_term.term.into_ir_def(generic_pointer_size),
            })
            .collect();
        let indirect_jmp_targets = self
            .jmps
            .iter()
            .find_map(|jmp_term| jmp_term.term.target_hints.clone())
            .unwrap_or_default();
        let jmps: Vec<Term<IrJmp>> = self
            .jmps
            .into_iter()
            .map(|jmp_term| Term {
                tid: jmp_term.tid,
                term: jmp_term.term.into(),
            })
            .collect();
        let indirect_jmp_targets = indirect_jmp_targets
            .into_iter()
            .map(|address| Tid::blk_id_at_address(&address))
            .collect();
        IrBlk {
            defs,
            jmps,
            indirect_jmp_targets,
        }
    }
}

impl Blk {
    /// Add `LOAD` instructions for implicit memory accesses
    /// to convert them to explicit memory accesses.
    fn add_load_defs_for_implicit_ram_access(&mut self, generic_pointer_size: ByteSize) {
        let mut refactored_defs = Vec::new();
        for def in self.defs.iter() {
            let mut cleaned_def = def.clone();
            if let Some(input) = &def.term.rhs.input0 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp0", generic_pointer_size);
                    cleaned_def.term.rhs.input0 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load0"),
                        term: load_def,
                    });
                }
            }
            if let Some(input) = &def.term.rhs.input1 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp1", generic_pointer_size);
                    cleaned_def.term.rhs.input1 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load1"),
                        term: load_def,
                    });
                }
            }
            if let Some(input) = &def.term.rhs.input2 {
                if input.address.is_some() {
                    let load_def = input.to_load_def("$load_temp2", generic_pointer_size);
                    cleaned_def.term.rhs.input2 = load_def.lhs.clone();
                    refactored_defs.push(Term {
                        tid: def.tid.clone().with_id_suffix("_load2"),
                        term: load_def,
                    });
                }
            }
            refactored_defs.push(cleaned_def);
        }

        for (index, jmp) in self.jmps.iter_mut().enumerate() {
            match jmp.term.mnemonic {
                JmpType::BRANCHIND | JmpType::CALLIND => {
                    let input = match jmp.term.mnemonic {
                        JmpType::BRANCHIND => match jmp.term.goto.as_mut().unwrap() {
                            Label::Indirect(expr) => expr,
                            Label::Direct(_) => panic!(),
                        },
                        JmpType::CALLIND => {
                            match jmp.term.call.as_mut().unwrap().target.as_mut().unwrap() {
                                Label::Indirect(expr) => expr,
                                Label::Direct(_) => panic!(),
                            }
                        }
                        _ => panic!(),
                    };
                    if input.address.is_some() {
                        let temp_register_name = format!("$load_temp{index}");
                        let load_def = input.to_load_def(temp_register_name, generic_pointer_size);
                        *input = load_def.lhs.clone().unwrap();
                        refactored_defs.push(Term {
                            tid: jmp.tid.clone().with_id_suffix("_load"),
                            term: load_def,
                        });
                    }
                }
                _ => (),
            }
        }
        self.defs = refactored_defs;
    }
}

/// An argument (parameter or return value) of an extern symbol.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Arg {
    /// The register containing the argument if it is passed in a register.
    pub var: Option<Variable>,
    /// The expression computing the location of the argument if it is passed on the stack.
    pub location: Option<Expression>,
    /// The intent (input or output) of the argument.
    pub intent: ArgIntent,
}

/// The intent (input or output) of a function argument.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum ArgIntent {
    /// The argument is an input parameter.
    INPUT,
    /// The argument is a return value.
    OUTPUT,
}

/// A subfunction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    /// The name of the function.
    pub name: String,
    /// The basic blocks of the function.
    ///
    /// Note that the first block of the array may *not* be the function entry point!
    pub blocks: Vec<Term<Blk>>,

    /// The calling convention used (as reported by Ghidra, i.e. this may not be correct).
    pub calling_convention: Option<String>,
}

impl Term<Sub> {
    /// Convert a `Sub` term in the P-Code representation to a `Sub` term in the intermediate representation.
    /// The conversion also repairs the order of the basic blocks in the `blocks` array of the `Sub`
    /// in the sense that the first block of the array is required to also be the function entry point
    /// after the conversion.
    pub fn into_ir_sub_term(mut self, generic_pointer_size: ByteSize) -> Term<IrSub> {
        // Since the intermediate representation expects that the first block of a function is its entry point,
        // we have to make sure that this actually holds.
        if !self.term.blocks.is_empty() && self.tid.address != self.term.blocks[0].tid.address {
            let mut start_block_index = None;
            for (i, block) in self.term.blocks.iter().enumerate() {
                if block.tid.address == self.tid.address {
                    start_block_index = Some(i);
                    break;
                }
            }
            if let Some(start_block_index) = start_block_index {
                self.term.blocks.swap(0, start_block_index);
            } else {
                panic!("Non-empty function without correct starting block encountered. Name: {}, TID: {}", self.term.name, self.tid);
            }
        }

        let blocks = self
            .term
            .blocks
            .into_iter()
            .map(|block_term| Term {
                tid: block_term.tid,
                term: block_term.term.into_ir_blk(generic_pointer_size),
            })
            .collect();
        Term {
            tid: self.tid,
            term: IrSub {
                name: self.term.name,
                blocks,
                calling_convention: self.term.calling_convention,
            },
        }
    }
}

/// An extern symbol, i.e. a function not contained in the binary but loaded from a shared library.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    /// The term identifier of the extern symbol.
    pub tid: Tid,
    /// The addresses to call the extern symbol.
    /// May be more than one, since we also identify thunk functions calling the extern symbol with the symbol itself.
    pub addresses: Vec<String>,
    /// The name of the extern symbol.
    pub name: String,
    /// The calling convention used (as reported by Ghidra, i.e. this may not be correct).
    pub calling_convention: Option<String>,
    /// The input and output arguments of the function.
    pub arguments: Vec<Arg>,
    /// If the function is assumed to never return to the caller, this flag is set to `true`.
    pub no_return: bool,
    /// If the function has a variable number of parameters, this flag is set to `true`.
    pub has_var_args: bool,
}

impl ExternSymbol {
    /// Artificially creates format string arguments as they are not detected by Ghidra.
    /// For scanf calls, the format string parameter is added to the function signature.
    /// For sscanf calls, the source and format string parameters are added to the function signature.
    fn create_format_string_args_for_scanf_and_sscanf(
        &mut self,
        conventions: &[CallingConvention],
        stack_pointer: &Variable,
        cpu_arch: &str,
    ) {
        let mut args: Vec<Arg> = Vec::new();
        if cpu_arch == "x86_32" {
            args.push(ExternSymbol::create_stack_arg(stack_pointer, 0));
            if self.name == "sscanf" || self.name == "__isoc99_sscanf" {
                args.push(ExternSymbol::create_stack_arg(
                    stack_pointer,
                    stack_pointer.size.as_bit_length(),
                ));
            }
        } else {
            args.push(self.create_register_arg(0, conventions, stack_pointer));
            if self.name == "sscanf" || self.name == "__isoc99_sscanf" {
                args.push(self.create_register_arg(1, conventions, stack_pointer));
            }
        }

        self.arguments.append(&mut args);
    }

    /// Matches the symbol's calling convention name and returns the desired integer parameter by index.
    fn get_symbol_parameter_by_index(
        &self,
        conventions: &[CallingConvention],
        index: usize,
    ) -> Option<String> {
        if let Some(cconv) = self.calling_convention.clone() {
            for convention in conventions.iter() {
                if convention.name == cconv {
                    return Some(
                        convention
                            .integer_parameter_register
                            .get(index)
                            .unwrap()
                            .clone(),
                    );
                }
            }
        }

        None
    }

    /// Creates a stack argument for scanf or sscanf calls.
    /// The address differs for both calls since the format string parameter is
    /// at a different position.
    fn create_stack_arg(stack_pointer: &Variable, address: usize) -> Arg {
        Arg {
            var: None,
            location: Some(Expression {
                mnemonic: ExpressionType::LOAD,
                input0: Some(Variable {
                    name: None,
                    value: None,
                    address: Some(format!(
                        "{:0width$x}",
                        address,
                        width = stack_pointer.size.as_bit_length()
                    )),
                    size: stack_pointer.size,
                    is_virtual: false,
                }),
                input1: None,
                input2: None,
            }),
            intent: ArgIntent::INPUT,
        }
    }

    /// Creates a register argument for scanf and sscanf calls.
    /// The format string index is different for each call.
    fn create_register_arg(
        &self,
        index: usize,
        conventions: &[CallingConvention],
        stack_pointer: &Variable,
    ) -> Arg {
        Arg {
            var: Some(Variable {
                name: self.get_symbol_parameter_by_index(conventions, index),
                value: None,
                address: None,
                size: stack_pointer.size,
                is_virtual: false,
            }),
            location: None,
            intent: ArgIntent::INPUT,
        }
    }

    /// Matches the symbols name with either scanf or sscanf.
    fn is_scanf_or_sscanf(&self) -> bool {
        matches!(
            self.name.as_str(),
            "scanf" | "sscanf" | "__isoc99_scanf" | "__isoc99_sscanf"
        )
    }

    /// Convert an extern symbol parsed from Ghidra to the internally used IR.
    fn into_ir_symbol(
        self,
        conventions: &[CallingConvention],
        stack_pointer: &Variable,
        cpu_arch: &str,
    ) -> IrExternSymbol {
        let mut symbol = self.clone();
        let mut parameters = Vec::new();
        let mut return_values = Vec::new();
        let symbol_has_input_args = symbol
            .arguments
            .iter()
            .any(|arg| matches!(arg.intent, ArgIntent::INPUT));
        if symbol.is_scanf_or_sscanf() && !symbol_has_input_args {
            symbol.create_format_string_args_for_scanf_and_sscanf(
                conventions,
                stack_pointer,
                cpu_arch,
            );
        }
        for arg in symbol.arguments.iter() {
            let ir_arg = if let Some(var) = arg.var.clone() {
                IrArg::Register {
                    expr: IrExpression::Var(var.into()),
                    data_type: None,
                }
            } else if let Some(expr) = arg.location.clone() {
                if expr.mnemonic == ExpressionType::LOAD {
                    let offset = i64::from_str_radix(
                        expr.input0
                            .clone()
                            .unwrap()
                            .address
                            .unwrap()
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    IrArg::Stack {
                        address: IrExpression::Var(stack_pointer.clone().into()).plus_const(offset),
                        size: expr.input0.unwrap().size,
                        data_type: None,
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
            tid: self.tid,
            addresses: self.addresses,
            name: self.name,
            calling_convention: self.calling_convention,
            parameters,
            return_values,
            no_return: symbol.no_return,
            has_var_args: symbol.has_var_args,
        }
    }
}

/// The program struct containing all information about the binary
/// except for CPU-architecture-related information.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Program {
    /// The subfunctions contained in the binary.
    pub subs: Vec<Term<Sub>>,
    /// The extern symbols referenced by the binary.
    pub extern_symbols: Vec<ExternSymbol>,
    /// The term identifiers of entry points into the binary.
    pub entry_points: Vec<Tid>,
    /// The base address of the memory image of the binary in RAM as reported by Ghidra.
    ///
    /// Note that Ghidra may add an offset to the image base address as reported by the binary itself.
    pub image_base: String,
}

impl Program {
    /// Convert a program parsed from Ghidra to the internally used IR.
    ///
    /// The `binary_base_address` denotes the base address of the memory image of the binary
    /// according to the program headers of the binary.
    /// It is needed to detect whether Ghidra added a constant offset to all addresses of the memory address.
    /// E.g. if the `binary_base_address` is 0 for shared object files,
    /// Ghidra adds an offset so that the memory image does not actually start at address 0.
    pub fn into_ir_program(
        self,
        binary_base_address: u64,
        conventions: &[CallingConvention],
        stack_pointer: &Variable,
        cpu_arch: &str,
    ) -> IrProgram {
        let subs = self
            .subs
            .into_iter()
            .map(|sub| (sub.tid.clone(), sub.into_ir_sub_term(stack_pointer.size)))
            .collect();
        let extern_symbols = self
            .extern_symbols
            .into_iter()
            .map(|symbol| {
                (
                    symbol.tid.clone(),
                    symbol.into_ir_symbol(conventions, stack_pointer, cpu_arch),
                )
            })
            .collect();
        let address_base_offset =
            u64::from_str_radix(&self.image_base, 16).unwrap() - binary_base_address;
        IrProgram {
            subs,
            extern_symbols,
            entry_points: self.entry_points.into_iter().collect(),
            address_base_offset,
        }
    }
}

/// A struct describing a calling convention.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConvention {
    /// The name of the calling convention.
    #[serde(rename = "calling_convention")]
    pub name: String,
    /// Possible integer parameter registers.
    integer_parameter_register: Vec<String>,
    /// Possible float parameter registers.
    float_parameter_register: Vec<String>,
    /// Possible integer return registers.
    return_register: Vec<String>,
    /// Possible float return registers.
    float_return_register: Vec<String>,
    /// Callee-saved registers.
    unaffected_register: Vec<String>,
    /// Registers that may be overwritten by the call, i.e. caller-saved registers.
    killed_by_call_register: Vec<String>,
}

impl CallingConvention {
    /// Convert a calling convention parsed from Ghidra to the internally used IR.
    fn into_ir_cconv(
        self,
        register_map: &HashMap<&String, &RegisterProperties>,
    ) -> IrCallingConvention {
        let to_ir_var_list = |list: Vec<String>| {
            list.into_iter()
                .map(|register_name| {
                    let reg = register_map.get(&register_name).cloned().unwrap();
                    assert_eq!(reg.register, reg.base_register);
                    reg.into()
                })
                .collect()
        };
        let to_ir_expression_list = |list: Vec<String>| {
            list.into_iter()
                .map(|register_name| {
                    let reg = register_map.get(&register_name).cloned().unwrap();
                    let mut expression = IrExpression::Var(reg.into());
                    expression = replace_input_subregister(expression, register_map);
                    expression
                })
                .collect()
        };
        let to_ir_base_var_list = |list: Vec<String>| {
            let register_set: BTreeSet<IrVariable> = list
                .into_iter()
                .map(|reg_name| {
                    let reg = register_map.get(&reg_name).unwrap();
                    let base_reg = *register_map.get(&reg.base_register).unwrap();
                    base_reg.into()
                })
                .collect();
            register_set.into_iter().collect()
        };
        IrCallingConvention {
            name: self.name,
            integer_parameter_register: to_ir_var_list(self.integer_parameter_register),
            float_parameter_register: to_ir_expression_list(self.float_parameter_register),
            integer_return_register: to_ir_var_list(self.return_register),
            float_return_register: to_ir_expression_list(self.float_return_register),
            // TODO / FIXME: Using `to_ir_base_var_list` is technically incorrect.
            // For example, on AArch64 only the bottom 64bit of some floating point registers are callee-saved.
            // To fix this one may have to to change callee_saved_register to a Vec<Expression>.
            callee_saved_register: to_ir_base_var_list(self.unaffected_register),
        }
    }
}

/// The project struct describing all known information about the binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Project {
    /// The program struct containing all binary-specific information.
    pub program: Term<Program>,
    /// The CPU-architecture that the binary uses.
    pub cpu_architecture: String,
    /// The stack pointer register of the CPU-architecture.
    pub stack_pointer_register: Variable,
    /// Information about all CPU-architecture-specific registers.
    pub register_properties: Vec<RegisterProperties>,
    /// Information about known calling conventions for the given CPU architecture.
    pub register_calling_convention: Vec<CallingConvention>,
    /// Contains the properties of C data types. (e.g. size)
    pub datatype_properties: DatatypeProperties,
}

impl Project {
    /// Convert a project parsed from Ghidra to the internally used IR.
    ///
    /// The `binary_base_address` denotes the base address of the memory image of the binary
    /// according to the program headers of the binary.
    pub fn into_ir_project(self, binary_base_address: u64) -> IrProject {
        let register_map: HashMap<&String, &RegisterProperties> = self
            .register_properties
            .iter()
            .map(|p| (&p.register, p))
            .collect();
        let mut program: Term<IrProgram> = Term {
            tid: self.program.tid,
            term: self.program.term.into_ir_program(
                binary_base_address,
                &self.register_calling_convention,
                &self.stack_pointer_register,
                &self.cpu_architecture,
            ),
        };
        // iterates over definitions and checks whether sub registers are used
        // if so, they are swapped with subpieces of base registers
        for sub in program.term.subs.values_mut() {
            for blk in sub.term.blocks.iter_mut() {
                super::subregister_substitution::replace_subregister_in_block(blk, &register_map);
            }
        }
        // Iterate over symbol arguments and replace used sub-registers
        for symbol in program.term.extern_symbols.values_mut() {
            for arg in symbol.parameters.iter_mut() {
                if let IrArg::Register { expr, .. } = arg {
                    *expr = replace_input_subregister(expr.clone(), &register_map);
                }
            }
            for arg in symbol.return_values.iter_mut() {
                if let IrArg::Register { expr, .. } = arg {
                    *expr = replace_input_subregister(expr.clone(), &register_map);
                }
            }
        }

        let register_set = self
            .register_properties
            .iter()
            .filter_map(|reg| {
                if reg.register == reg.base_register {
                    Some(reg.into())
                } else {
                    None
                }
            })
            .collect();
        let calling_conventions = self
            .register_calling_convention
            .clone()
            .into_iter()
            .map(|cconv| (cconv.name.clone(), cconv.into_ir_cconv(&register_map)))
            .collect();
        IrProject {
            program,
            cpu_architecture: self.cpu_architecture,
            stack_pointer_register: self.stack_pointer_register.into(),
            calling_conventions,
            register_set,
            datatype_properties: self.datatype_properties.clone(),
            runtime_memory_image: RuntimeMemoryImage::empty(true),
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
    ///
    /// ### Remove basic blocks of functions without correct starting block
    ///
    /// Sometimes Ghidra generates a (correct) function start inside another function.
    /// But if the function start is not also the start of a basic block,
    /// we cannot handle it correctly (yet) as this would need splitting of basic blocks.
    /// So instead we generate a log message and handle the function as a function without code,
    /// i.e. a dead end in the control flow graph.
    #[must_use]
    pub fn normalize(&mut self) -> Vec<LogMessage> {
        let mut log_messages = Vec::new();

        // Insert explicit `LOAD` instructions for implicit memory loads in P-Code.
        let generic_pointer_size = self.stack_pointer_register.size;
        for sub in self.program.term.subs.iter_mut() {
            for block in sub.term.blocks.iter_mut() {
                block
                    .term
                    .add_load_defs_for_implicit_ram_access(generic_pointer_size);
            }
        }

        // remove all blocks from functions that have no correct starting block and generate a log-message.
        for sub in self.program.term.subs.iter_mut() {
            if !sub.term.blocks.is_empty()
                && sub.tid.address != sub.term.blocks[0].tid.address
                && !sub
                    .term
                    .blocks
                    .iter()
                    .any(|block| block.tid.address == sub.tid.address)
            {
                log_messages.push(LogMessage::new_error(format!(
                    "Starting block of function {} ({}) not found.",
                    sub.term.name, sub.tid
                )));
                sub.term.blocks = Vec::new();
            }
        }

        log_messages
    }
}

#[cfg(test)]
mod tests;
