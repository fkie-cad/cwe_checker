//! This module defines the interface for parsing ghidra pcode provided by `PcodeExtractor.java`.
//! The JSON representation is parsed and translated into `cwe_checker`'s [intermediate represnetation](crate::intermediate_representation).
//! Additionally, following normalization steps are performed:
//! * implicit load operations are converted into explitict [Def::Load] representation.

use crate::intermediate_representation::*;
use crate::pcode::ExpressionType;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
mod pcode_operations;
use pcode_operations::*;
mod pcode_op_simple;
use pcode_op_simple::*;

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
        let mut targets: HashSet<u64> = HashSet::new();
        for func in self.functions {
            for blk in func.blocks {
                let t = &blk.collect_jmp_targets();
                targets.extend(t.iter());
                for inst in blk.instructions {
                    for mut op in inst.pcode_ops {
                        if matches!(op.pcode_mnemonic, PcodeOperation::ExpressionType(_)) {
                            op.into_ir_def(&inst.address);
                        }
                    }
                }
            }
            //dbg!(&targets);
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

    /// Returns `Term<Def::Load>`, if the varnode describes an implicit load operation.
    ///
    /// Changes the varnode's `id` and `address_space` to the virtual variable.
    ///
    /// Panics, if varnode's address_space is not `ram`
    fn into_explicit_load(
        &mut self,
        var_name: String,
        tid_suffix: String,
        address: &String,
        pcode_index: u64,
    ) -> Term<Def> {
        let load = Def::Load {
            var: Variable {
                name: var_name.clone(),
                size: self.size.into(),
                is_temp: true,
            },
            address: Expression::Const(
                self.get_ram_address()
                    .expect("varnode's addressspace is not ram"),
            ),
        };

        // Change varnode to newly introduced explicit variable
        self.id = var_name.into();
        self.address_space = "unique".into();

        Term {
            tid: Tid {
                id: format!("instr_{}_{}_{}", address, pcode_index, tid_suffix),
                address: address.to_string(),
            },
            term: load,
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
    fn into_ir_def(self) {
        let mut ops = vec![];
        for mut op in self.pcode_ops {
            ops.append(&mut op.into_ir_def(&self.address))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BlockSimple {
    pub address: String,
    pub instructions: Vec<InstructionSimple>,
}

impl BlockSimple {
    fn collect_jmp_targets(&self) -> HashSet<u64> {
        // Collecting jump targets for splitting up blocks
        let mut jump_targets = HashSet::new();
        for instr in &self.instructions {
            // create a set of all jump targets
            for op in &instr.pcode_ops {
                match op.get_jump_target() {
                    Some(JmpTarget::Absolut(target_addr)) => {
                        jump_targets.insert(target_addr);
                    }
                    Some(JmpTarget::Relative((start_index, target_index))) => {
                        self.get_if_relative_jump_to_next_instruction(
                            instr,
                            start_index as usize,
                            target_index as usize,
                        )
                        .map(|addr| jump_targets.insert(addr));
                    }

                    _ => (),
                };
            }
        }
        jump_targets
    }

    /// Returns the following instruction of the block, if a pcode relative jump exceeds the amount of the instructions's pcode operations.
    ///
    /// If the pcode relative jump's target is within the array of the instruction's pcode operations,
    /// `None` is returned.
    fn get_if_relative_jump_to_next_instruction(
        &self,
        jump_site: &InstructionSimple,
        start_index: usize,
        offset_to_target: usize,
    ) -> Option<u64> {
        let mut instruction_sequence = self.instructions.iter().peekable();
        while let Some(instr) = instruction_sequence.next() {
            if instr == jump_site && instr.pcode_ops.capacity() < (start_index + offset_to_target) {
                if let Some(target_instr) = instruction_sequence.peek() {
                    dbg!(&jump_site.pcode_ops[start_index]);
                    return Some(
                        u64::from_str_radix(&target_instr.address.trim_start_matches("0x"), 16)
                            .expect("Cannot parse address"),
                    );
                } else {
                    panic!("Pcode relative jump to next instruction, but block does not have instructions left")
                }
            }
        }

        None
    }
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
