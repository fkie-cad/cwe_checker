#![allow(unreachable_code)]

use crate::intermediate_representation::*;
use crate::pcode::ExpressionType;
use crate::pcode::JmpType::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

mod pcode_operations;
use pcode_operations::*;
mod pcode_op_simple;
use pcode_op_simple::*;
mod varnode;
use varnode::*;
mod instruction;
use instruction::*;
mod block;
use block::*;
mod function;
use function::*;

/// The project struct for deserialization of the ghidra pcode extractor JSON.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PcodeProject {
    /// The program struct containing all binary-specific information.
    functions: Vec<Function>,
    /// Information about all CPU-architecture-specific registers.
    register_properties: Vec<RegisterProperties>,
    /// The CPU-architecture that the binary uses.
    cpu_arch: String,
    // External functions with name of the binary.
    external_functions: HashMap<String, ExternFunction>,
    // Entry points into the binary.
    entry_points: Vec<String>,
    /// The stack pointer register of the CPU-architecture.
    stack_pointer_register: Varnode,
    /// Information about known calling conventions for the given CPU architecture.
    calling_conventions: HashMap<String, CallingConvention>,
    /// Contains the properties of C data types. (e.g. size)
    datatype_properties: DatatypeProperties,
    // Image base address in memory
    image_base: String,
}

impl PcodeProject {
    pub fn into_ir_project(self) -> Project {
        let mut jump_targets: HashSet<Tid> = HashSet::new();
        for func in &self.functions {
            for blk in func.blocks() {
                let targets = blk.collect_jmp_targets();
                jump_targets.extend(targets.into_iter());
            }
        }

        for func in self.functions {
            for blk in func.into_blocks() {
                let _blocks = blk.into_ir_blk(&jump_targets);
                // TODO
            }
        }

        todo!(); // TODO: Normalization-Pass that replaces pseudo-call-target-TIDs with the correct target-TID
                 // of the corresponding function.
        todo!(); // TODO: Check that we somewhere replace indirect calls with a constant target
                 // with a direct call. Maybe do the same for indirect branches?

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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RegisterProperties {
    register_name: String,
    base_register: String,
    lsb: u64,
    size: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DatatypeProperties {
    char_size: u64,
    double_size: u64,
    float_size: u64,
    integer_size: u64,
    long_double_size: u64,
    long_long_size: u64,
    long_size: u64,
    pointer_size: u64,
    short_size: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConvention {
    name: String,
    integer_parameter_register: Vec<Varnode>,
    float_parameter_register: Vec<Varnode>,
    integer_return_register: Varnode,
    float_return_register: Option<Varnode>,
    unaffected_register: Vec<Varnode>,
    killed_by_call_register: Vec<Varnode>,
}

#[cfg(test)]
mod tests;
