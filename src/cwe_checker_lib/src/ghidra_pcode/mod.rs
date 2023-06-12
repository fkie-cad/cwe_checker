//! This module defines the interface for parsing ghidra pcode provided by `PcodeExtractor.java`.
//! The JSON representation is parsed and translatet into `cwe_checker`'s [intermediate represnetation](crate::intermediate_representation).
//! Additionally, following normalization steps are performed:
//! * implicit load operations are converted into explitict [Def::Load] representation.

use crate::intermediate_representation::*;
use crate::pcode::{ExpressionType, JmpType};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The project struct for deserialization of the ghidra pcode extractor JSON.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ProjectSimple {
    /// The program struct containing all binary-specific information.
    pub functions: Vec<FunctionSimple>,
    /// Information about all CPU-architecture-specific registers.
    pub register_properties: Vec<RegisterProperties>,
    /// The CPU-architecture that the binary uses.
    pub cpu_arch: String,
    // External functions with name of the binary.
    pub external_functions: HashMap<String, ExternFunctionSimple>,
    // Entry points into the binary.
    pub entry_points: Vec<String>,
    /// The stack pointer register of the CPU-architecture.
    pub stack_pointer_register: VarnodeSimple,
    /// Information about known calling conventions for the given CPU architecture.
    pub conventions: HashMap<String, CallingConventionsProperties>,
    /// Contains the properties of C data types. (e.g. size)
    pub datatype_properties: DatatypeProperties,
    // Image base address in memory
    pub imagebase: String,
}

impl ProjectSimple {
    pub fn into_ir_project(self) -> Project {
        for func in self.functions {
            for blk in func.blocks {
                for inst in blk.instructions {
                    for op in inst.pcode_ops {
                        if PcodeOperation::ExpressionType(ExpressionType::LOAD) == op.pcode_mnemonic
                            || PcodeOperation::ExpressionType(ExpressionType::STORE)
                                == op.pcode_mnemonic
                        {
                            println!("{:?}", op.pcode_mnemonic);
                            println!("{:?}", op.into_ir_def(&inst.address));
                        }
                    }
                }
            }
        }

        Project {
            program: todo!(),
            cpu_architecture: todo!(),
            stack_pointer_register: todo!(),
            calling_conventions: todo!(),
            register_set: todo!(),
            datatype_properties: todo!(),
            runtime_memory_image: todo!(),
        }
    }
}

/// The Varnode struct for deserialization of the ghidra pcode extractor JSON.
///
/// Varnode is a class used by ghidra for modeling a location within an addressspace and size, e.g. a specific
/// register.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct VarnodeSimple {
    /// Addressspace, e.g. register or constant
    pub addressspace: String,
    /// Offset (value) in addressspace, or register name
    pub id: String,
    /// Size of the varnode
    pub size: u64,
}
impl VarnodeSimple {
    /// Translates into `Expression::Const` for constants or `Expression::Var` for registers or
    /// virtual registers.
    ///
    /// Returns `Err` if the addressspace is neither `"const"`, `"register"` nor `"unique"`.
    fn into_ir_expr(self) -> Result<Expression> {
        println!("\t{} : {} : {}", self.addressspace, self.id, self.size);
        match self.addressspace.as_str() {
            "const" => Ok(Expression::Const(Bitvector::from_u64(u64::from_str_radix(
                &self.id.trim_start_matches("0x"),
                16,
            )?))),
            "register" => Ok(Expression::Var(Variable {
                name: self.id,
                size: ByteSize::new(self.size),
                is_temp: false,
            })),
            "unique" => Ok(Expression::Var(Variable {
                name: format!("$U_{}", self.id),
                size: ByteSize::new(self.size),
                is_temp: true,
            })),
            _ => Err(anyhow!("Varnode translation failed.")),
        }
    }

    /// Returns `Bitvector` representing a constant address in ram, if
    /// the varnode represents such address.
    /// Panics if the address cannot be parsed.
    fn get_ram_address(&self) -> Option<Bitvector> {
        match self.addressspace.as_str() {
            "ram" => Some(Bitvector::from_u64(
                u64::from_str_radix(&self.id.trim_start_matches("0x"), 16)
                    .expect(&format!("Cannot parse {}", &self.id)),
            )),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PcodeOpSimple {
    pub pcode_index: u64,
    pub pcode_mnemonic: PcodeOperation,
    pub input0: VarnodeSimple,
    pub input1: Option<VarnodeSimple>,
    pub input2: Option<VarnodeSimple>,
    pub output: Option<VarnodeSimple>,
}

impl PcodeOpSimple {
    /// Returns `true` if at least one input is ram located.
    fn has_implicit_load(&self) -> bool {
        if self.input0.addressspace == "ram" {
            return true;
        }
        if let Some(varnode) = &self.input1 {
            if varnode.addressspace == "ram" {
                return true;
            }
        }
        if let Some(varnode) = &self.input2 {
            if varnode.addressspace == "ram" {
                return true;
            }
        }
        false
    }
    // Returns `true` if the output is ram located.
    fn has_implicit_store(&self) -> bool {
        if let Some(varnode) = &self.output {
            if varnode.addressspace == "ram" {
                return true;
            }
        }
        false
    }
    /// Returns artificial `Def::Load` instructions, if the operants are ram located.
    /// Otherwise returns empty `Vec`.
    ///
    /// The created instructions use the virtual register `$load_tempX`, whereby `X` is
    /// either `0` or `1`representing which input is used.
    /// The created `Tid` is named `instr_<address>_<pcode index>_load<X>`.
    fn create_implicit_loads(&self, address: &String) -> Vec<Term<Def>> {
        let mut explicit_loads = vec![];
        if self.input0.addressspace == "ram" {
            let load0 = Def::Load {
                var: Variable {
                    name: "$load_temp0".into(),
                    size: self.input0.size.into(),
                    is_temp: true,
                },
                address: Expression::Const(
                    self.input0
                        .get_ram_address()
                        .expect("varnode's addressspace is not ram"),
                ),
            };
            explicit_loads.push(Term {
                tid: Tid {
                    id: format!("instr_{}_{}_load0", address, self.pcode_index),
                    address: address.to_string(),
                },
                term: load0,
            })
        }
        if let Some(varnode) = &self.input1 {
            if varnode.addressspace == "ram" {
                let load1 = Def::Load {
                    var: Variable {
                        name: "$load_temp1".into(),
                        size: varnode.size.into(),
                        is_temp: true,
                    },
                    address: Expression::Const(
                        varnode
                            .get_ram_address()
                            .expect("varnode's addressspace is not ram"),
                    ),
                };
                explicit_loads.push(Term {
                    tid: Tid {
                        id: format!("instr_{}_{}_load1", address, self.pcode_index),
                        address: address.to_string(),
                    },
                    term: load1,
                })
            }
        }

        explicit_loads
    }

    /// Translates a single pcode operation into at leas one `Def`.
    ///
    /// Adds additional `Def::Load`, if the pcode operation performs implicit loads from ram
    fn into_ir_def(self, address: &String) -> Vec<Term<Def>> {
        let mut defs = vec![];
        // if the pcode operation contains implicit load operations, prepend them.
        if self.has_implicit_load() {
            let mut explicit_loads = self.create_implicit_loads(address);
            defs.append(&mut explicit_loads);
        }

        let def = match self.pcode_mnemonic {
            PcodeOperation::ExpressionType(expr_type) => self.create_def(address, expr_type),
            PcodeOperation::JmpType(jmp_type) => todo!(),
        };

        defs.push(def);
        defs
    }

    /// Creates `Def::Store`, `Def::Load` or `Def::Assign` according to the pcode operations'
    /// expression type.
    fn create_def(self, address: &String, expr_type: ExpressionType) -> Term<Def> {
        match expr_type {
            ExpressionType::LOAD => self.create_load(address),
            ExpressionType::STORE => self.create_store(address),
            _ => todo!(),
        }
    }

    /// Translates pcode load operation into `Def::Load`
    ///
    /// Pcode load instruction:
    /// https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcodedescription.html#cpui_load
    /// Note: input0 ("Constant ID of space to load from") is not considered.
    ///
    /// Panics, if any of the following applies:
    /// * `output` is `None`
    /// * load destination is not a variable
    /// * `input1` is `None`
    /// * `into_ir_expr()` returns `Err` on any varnode
    fn create_load(self, address: &String) -> Term<Def> {
        if !matches!(
            self.pcode_mnemonic,
            PcodeOperation::ExpressionType(ExpressionType::LOAD)
        ) {
            panic!("Pcode operation is not LOAD")
        }
        let target = self.output.expect("Load without output");
        if let Expression::Var(var) = target
            .into_ir_expr()
            .expect("Load target translation failed")
        {
            let source = self
                .input1
                .expect("Load without source")
                .into_ir_expr()
                .expect("Load source address translation failed");

            let def = Def::Load {
                var,
                address: source,
            };
            return Term {
                tid: Tid {
                    id: format!("instr_{}_{}", address, self.pcode_index),
                    address: address.to_string(),
                },
                term: def,
            };
        } else {
            panic!("Load target is not a variable")
        }
    }

    /// Translates pcode store operation into `Def::Load`
    ///
    /// Pcode load instruction:
    /// https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcodedescription.html#cpui_store
    /// Note: input0 ("	Constant ID of space to store into") is not considered.
    ///
    /// Panics, if any of the following applies:
    /// * `input1` is None
    /// * `input2` is None
    /// * `into_ir_expr()` returns `Err` on any varnode
    fn create_store(self, address: &String) -> Term<Def> {
        if !matches!(
            self.pcode_mnemonic,
            PcodeOperation::ExpressionType(ExpressionType::STORE)
        ) {
            panic!("Pcode operation is not STORE")
        }
        let target_expr = self
            .input1
            .expect("Store without target")
            .into_ir_expr()
            .expect("Store target translation failed.");

        let source = self.input2.expect("Store without source");
        if !matches!(
            source.addressspace.as_str(),
            "unique" | "const" | "variable"
        ) {
            panic!("Store source is not a variable, temp variable nor constant.")
        }

        let source_expr = source
            .into_ir_expr()
            .expect("Store source translation failed");
        let def = Def::Store {
            address: target_expr,
            value: source_expr,
        };

        return Term {
            tid: Tid {
                id: format!("instr_{}_{}", address, self.pcode_index),
                address: address.to_string(),
            },
            term: def,
        };
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct InstructionSimple {
    pub mnemonic: String,
    pub address: String,
    pub pcode_ops: Vec<PcodeOpSimple>,
    pub potential_targets: Option<Vec<String>>,
}

impl InstructionSimple {
    fn into_ir_def(&self) {}
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BlockSimple {
    pub address: String,
    pub instructions: Vec<InstructionSimple>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FunctionSimple {
    pub name: String,
    pub address: String,
    pub blocks: Vec<BlockSimple>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RegisterProperties {
    pub register_name: String,
    pub base_register: String,
    pub lsb: u64,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternFunctionSimple {
    pub name: String,
    pub calling_convention: String,
    pub parameters: Vec<VarnodeSimple>,
    pub return_location: Option<VarnodeSimple>,
    pub thunks: Vec<String>,
    pub has_no_return: bool,
    pub has_var_args: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DatatypeProperties {
    pub char_size: u64,
    pub double_size: u64,
    pub float_size: u64,
    pub integer_size: u64,
    pub long_double_size: u64,
    pub long_long_size: u64,
    pub long_size: u64,
    pub pointer_size: u64,
    pub short_size: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConventionsProperties {
    pub name: String,
    pub integer_parameter_register: Vec<VarnodeSimple>,
    pub float_parameter_register: Vec<VarnodeSimple>,
    pub integer_return_register: VarnodeSimple,
    pub float_return_register: Option<VarnodeSimple>,
    pub unaffected_register: Vec<VarnodeSimple>,
    pub killed_by_call_register: Vec<VarnodeSimple>,
}

/// P-Code operation wrapper type
///
/// Wrapps expression and jump types for direct deserializations.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum PcodeOperation {
    ExpressionType(ExpressionType),
    JmpType(JmpType),
}

#[cfg(test)]
mod tests;
