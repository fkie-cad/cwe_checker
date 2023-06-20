//! This module defines the interface for parsing ghidra pcode provided by `PcodeExtractor.java`.
//! The JSON representation is parsed and translated into `cwe_checker`'s [intermediate represnetation](crate::intermediate_representation).
//! Additionally, following normalization steps are performed:
//! * implicit load operations are converted into explitict [Def::Load] representation.

use crate::intermediate_representation::*;
use crate::pcode::{ExpressionType, JmpType};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
mod pcode_operations;
use pcode_operations::*;

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
                        if matches!(op.pcode_mnemonic, PcodeOperation::ExpressionType(_)) {
                            dbg!(&op);
                            op.into_ir_def(&inst.address);
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
    pub address_space: String,
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
    fn into_ir_expr(&self) -> Result<Expression> {
        match self.address_space.as_str() {
            "const" => {
                let constant =
                    Bitvector::from_u64(u64::from_str_radix(self.id.trim_start_matches("0x"), 16)?);

                Ok(Expression::Const(
                    constant.into_resize_unsigned(self.size.into()),
                ))
            }
            "register" => Ok(Expression::Var(Variable {
                name: self.id.clone(),
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
        if self.address_space.as_str() == "ram" {
            let offset = Bitvector::from_u64(
                u64::from_str_radix(self.id.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("Cannot parse {}", &self.id)),
            );
            return Some(offset.into_resize_unsigned(self.size.into()));
        }
        None
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
        if self.input0.address_space == "ram" {
            return true;
        }
        if let Some(varnode) = &self.input1 {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        if let Some(varnode) = &self.input2 {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        false
    }
    // Returns `true` if the output is ram located.
    fn has_implicit_store(&self) -> bool {
        if let Some(varnode) = &self.output {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        false
    }
    /// Returns artificial `Def::Load` instructions, if the operants are ram located.
    /// Otherwise returns empty `Vec`. Changes ram varnodes into virtual register varnodes
    /// using the explicitly loaded value.
    ///
    /// The created instructions use the virtual register `$load_tempX`, whereby `X` is
    /// either `0`, `1`or `2` representing which input is used.
    /// The created `Tid` is named `instr_<address>_<pcode index>_load<X>`.
    fn create_implicit_loads(&mut self, address: &String) -> Vec<Term<Def>> {
        let mut explicit_loads = vec![];
        if self.input0.address_space == "ram" {
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
            });

            // Change varnode to virtual register
            self.input0.id = "$load_temp0".into();
            self.input0.address_space = "unique".into();
        }
        if let Some(varnode) = &self.input1 {
            if varnode.address_space == "ram" {
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
                });

                // Change varnode to virtual register
                self.input0.id = "$load_temp1".into();
                self.input0.address_space = "unique".into();
            }
        }

        if let Some(varnode) = &self.input2 {
            if varnode.address_space == "ram" {
                let load2 = Def::Load {
                    var: Variable {
                        name: "$load_temp2".into(),
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
                        id: format!("instr_{}_{}_load2", address, self.pcode_index),
                        address: address.to_string(),
                    },
                    term: load2,
                });

                // Change varnode to virtual register
                self.input0.id = "$load_temp1".into();
                self.input0.address_space = "unique".into();
            }
        }

        explicit_loads
    }

    /// Translates a single pcode operation into at leas one `Def`.
    ///
    /// Adds additional `Def::Load`, if the pcode operation performs implicit loads from ram
    fn into_ir_def(mut self, address: &String) -> Vec<Term<Def>> {
        let mut defs = vec![];
        // if the pcode operation contains implicit load operations, prepend them.
        if self.has_implicit_load() {
            let mut explicit_loads = self.create_implicit_loads(address);
            defs.append(&mut explicit_loads);
        }
        if self.has_implicit_store() {
            todo!()
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
            ExpressionType::COPY => self.create_assign(address),
            _ if expr_type.into_ir_unop().is_some() => self.create_unop(address),
            _ if expr_type.into_ir_biop().is_some() => self.create_biop(address),
            _ if expr_type.into_ir_cast().is_some() => self.create_castop(address),
            _ => panic!("Unsupported pcode operation"),
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
            Term {
                tid: Tid {
                    id: format!("instr_{}_{}", address, self.pcode_index),
                    address: address.to_string(),
                },
                term: def,
            }
        } else {
            panic!("Load target is not a variable")
        }
    }

    /// Translates pcode store operation into `Def::Store`
    ///
    /// Pcode load instruction:
    /// https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcodedescription.html#cpui_store
    /// Note: input0 ("Constant ID of space to store into") is not considered.
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

        let data = self.input2.expect("Store without source data");
        if !matches!(data.address_space.as_str(), "unique" | "const" | "variable") {
            panic!("Store source data is not a variable, temp variable nor constant.")
        }

        let source_expr = data
            .into_ir_expr()
            .expect("Store source translation failed");
        let def = Def::Store {
            address: target_expr,
            value: source_expr,
        };

        Term {
            tid: Tid {
                id: format!("instr_{}_{}", address, self.pcode_index),
                address: address.to_string(),
            },
            term: def,
        }
    }

    /// Translates pcode operation with one input into `Term<Def>` with unary `Expression`.
    /// The mapping is implemented in `into_ir_unop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output` or `self.input0`
    fn create_unop(self, address: &String) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::UnOp {
                op: expr_type
                    .into_ir_unop()
                    .expect("Translation into unary operation type failed"),
                arg: Box::new(self.input0.into_ir_expr().unwrap()),
            };
            return self.wrap_in_assign(address, expr);
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates a pcode operation with two inputs into `Term<Def>` with binary `Expression`.
    /// The mapping is implemented in `into_ir_biop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output`, `self.input0` or `self.input1`
    pub fn create_biop(self, address: &String) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::BinOp {
                op: expr_type
                    .into_ir_biop()
                    .expect("Translation into binary operation type failed"),
                lhs: Box::new(self.input0.into_ir_expr().unwrap()),
                rhs: Box::new(
                    self.input1
                        .clone()
                        .expect("No input 1 for binary operation")
                        .into_ir_expr()
                        .unwrap(),
                ),
            };
            return self.wrap_in_assign(address, expr);
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates a cast pcode operation into `Term<Def>` with `Expression::Cast`.
    /// The mapping is implemented in `into_ir_castop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output` or `self.input0`
    pub fn create_castop(self, address: &String) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::Cast {
                op: expr_type
                    .into_ir_cast()
                    .expect("Translation into cast operation failed"),
                size: self
                    .output
                    .clone()
                    .expect("No output for cast operation")
                    .size
                    .into(),
                arg: Box::new(self.input0.into_ir_expr().unwrap()),
            };
            return self.wrap_in_assign(address, expr);
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates PcodeOperation::COPY into Term<Def::Assign>.
    pub fn create_assign(self, address: &String) -> Term<Def> {
        if let PcodeOperation::ExpressionType(ExpressionType::COPY) = self.pcode_mnemonic {
            let expr = self.input0.into_ir_expr().unwrap();
            return self.wrap_in_assign(address, expr);
        } else {
            panic!("PcodeOperation is not COPY")
        }
    }

    /// Helper function for creating Assign operations.
    ///
    /// Panics if,
    /// * self.output is `None` or `into_ir_expr()` returns `Err`
    /// * self.output is not `Expression::Var`
    pub fn wrap_in_assign(self, address: &String, expr: Expression) -> Term<Def> {
        if let Expression::Var(var) = self
            .output
            .expect("No output varnode")
            .into_ir_expr()
            .unwrap()
        {
            let tid = Tid {
                id: format!("instr_{}_{}", address, self.pcode_index),
                address: address.to_string(),
            };
            return Term {
                tid,
                term: Def::Assign { var, value: expr },
            };
        } else {
            panic!("Output varnode is not a variable")
        }
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
    fn into_ir_def(&self) {
        todo!()
    }
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

#[cfg(test)]
mod tests;
