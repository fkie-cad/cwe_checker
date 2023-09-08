//! This module defines the interface for parsing ghidra pcode provided by `PcodeExtractor.java`.
//! The JSON representation is parsed and translated into `cwe_checker`'s [intermediate represnetation](crate::intermediate_representation).
//! Additionally, following normalization steps are performed:
//! * implicit load operations are converted into explitict [Def::Load] representation.

use crate::intermediate_representation::*;
use crate::pcode::ExpressionType;
use crate::pcode::JmpType::*;
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
        let mut jump_targets: HashSet<Tid> = HashSet::new();
        for func in &self.functions {
            for blk in &func.blocks {
                let targets = blk.collect_jmp_targets();
                jump_targets.extend(targets.into_iter());
            }
        }

        for func in self.functions {
            for blk in func.blocks {
                blk.into_ir_blk(&jump_targets);
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
    pub size: u64,
    pub pcode_ops: Vec<PcodeOpSimple>,
    pub potential_targets: Option<Vec<String>>,
    pub fall_through: Option<String>,
}

impl InstructionSimple {
    /// Returns the instruction field as `u64`.
    pub fn get_u64_address(&self) -> u64 {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16).unwrap()
    }

    /// Returns the fallthrough address of the instruction using the following order:
    /// 1) `instructions.fall_through` if `Some`
    /// 2) provided consecutive instruction's address
    /// 3) compute instructuins address + instruction size
    pub fn get_best_guess_fallthrough_addr(
        &self,
        consecutive_instr: Option<&InstructionSimple>,
    ) -> String {
        match &self.fall_through {
            Some(fallthrough_instr_addr) => fallthrough_instr_addr.clone(),
            // If no fallthrough information available, first try following instruction in block
            // else compute next instruction
            None => {
                if let Some(next_instr) = consecutive_instr {
                    next_instr.address.clone()
                } else {
                    format!("{:x}", self.get_u64_address() + self.size)
                }
            }
        }
    }

    /// Collects all jump targets of an instruction and returns their `Tid`.
    /// The id follows the naming convention `blk_<address>`. If the target is within
    /// a pcode sequence and the index is larger 0, `_<pcode_index>` is suffixed.
    pub fn collect_jmp_targets(
        &self,
        consecutive_instr: Option<&InstructionSimple>,
    ) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();
        for op in &self.pcode_ops {
            if matches!(op.pcode_mnemonic, PcodeOperation::JmpType(_)) {
                let best_guess_fallthrough_address =
                    self.get_best_guess_fallthrough_addr(consecutive_instr);

                let targets = op.collect_jmp_targets(
                    self.address.clone(),
                    self.pcode_ops.len() as u64,
                    best_guess_fallthrough_address,
                );
                jump_targets.extend(targets)
            }
        }
        jump_targets
    }
}

/// Iterator for processing a block's sequence of instructions and their pcode operations.
/// For creating Tids of implicit branches, we need to be able to have a look at the previous operation.
/// For creating jumps to consecutive blocks, wee need to be able to have a look at the next operation.
/// For all cases we need to know the corresponding Instruction-Pcode-Pair for deriving the correct address and Tid.
struct OpIterator {
    instructions: Vec<InstructionSimple>,
    operations: Vec<PcodeOpSimple>,
    current_instr_index: Option<u64>,
    current_op_index: Option<u64>,
}

impl OpIterator {
    fn get_current_instr(&self) -> Option<InstructionSimple> {
        todo!()
    }

    fn get_current_op(&self) -> Option<PcodeOpSimple> {
        todo!()
    }

    fn get_current_pair(&self) -> Option<(InstructionSimple, PcodeOpSimple)> {
        todo!()
    }

    fn next(&self) -> Option<(InstructionSimple, PcodeOpSimple)> {
        todo!()
    }

    fn get_next_instr(&self) -> Option<InstructionSimple> {
        todo!()
    }

    fn get_next_op(&self) -> Option<PcodeOpSimple> {
        todo!()
    }

    fn get_blk_tid_of_current_operation(&self) -> Tid {
        todo!()
    }

    fn get_last_operation_pair(&self) -> Option<(InstructionSimple, PcodeOpSimple)> {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BlockSimple {
    pub address: String,
    pub instructions: Vec<InstructionSimple>,
}

impl BlockSimple {
    fn get_op_iterator(&self) -> OpIterator {
        todo!()
    }

    /// Collects all jumps targets of instructions within the block.
    ///
    /// A block `Tid`is created for every target using the id scheme `blk_<addr>_<index>`, with
    /// `<index>` denoting the pcode operation index for intra instruction jumps. `<addr>` denotes the address
    /// of the target block, that might be created additionally to Ghidras basic blocks.
    /// If a pcode relative jump implies a jump to the next instruction, the instruction's address is derived in the following order:
    /// 1. use instructions's falltrough address
    /// 2. use the block's consecutive instruction
    /// 3. compute the address
    fn collect_jmp_targets(&self) -> HashSet<Tid> {
        // Collecting jump targets for splitting up blocks
        let mut jump_targets = HashSet::new();
        let mut instructions = self.instructions.iter().peekable();

        while let Some(instr) = instructions.next() {
            jump_targets.extend(instr.collect_jmp_targets(instructions.peek().copied()))
        }
        jump_targets
    }

    /// Translates a Basic block by Ghidra into one or many IR basic blocks.
    fn into_ir_blk(self, jump_targets: &HashSet<Tid>) -> Vec<Term<Blk>> {
        let mut finalized_blocks = vec![];

        // The iterator provides the currently pcode operation together with its instruction.
        let mut iterator = self.get_op_iterator();

        // While a current operation is present, translate it and add it to a block...
        while let Some((instr, op)) = iterator.get_current_pair() {
            let tid = generate_new_tid(instr.address.clone(), op.pcode_index);

            // add_defs_to_block() processes the current operation and following, until:
            // A) a jump target is reached
            // B) the current operation is a jump operation
            //  This function might change the current operation.
            let blk = add_defs_to_block(Blk::new(), &mut iterator, jump_targets);
            // At this point, the current operation is either a target or a jump instruction.

            // This is used to finish a block.
            let finished_blk = finish_blk(blk, &mut iterator, jump_targets);
            let finalized_blk = Term {
                tid,
                term: finished_blk,
            };
            finalized_blocks.push(finalized_blk);
        }
        finalized_blocks
    }
}

/// Generates a block tid using the naming convention.
fn generate_new_tid(address: String, pcode_index: u64) -> Tid {
    let id = match pcode_index {
        0 => format!("blk_{}", address),
        _ => format!("blk_{}_{}", address, pcode_index),
    };
    Tid { id, address }
}

/// Uses the iterator to translate current operation and following into Defs and adds them to the block.
/// Returns if current operation is a jump target, or a jump operation.
fn add_defs_to_block(mut blk: Blk, iterator: &mut OpIterator, jump_targets: &HashSet<Tid>) -> Blk {
    if jump_targets.contains(&iterator.get_blk_tid_of_current_operation()) {
        return blk;
    }
    if matches!(
        iterator.get_current_op().unwrap().pcode_mnemonic,
        PcodeOperation::JmpType(_)
    ) {
        return blk;
    }
    // Add current operation to block
    blk.defs.append(
        &mut iterator
            .get_current_op()
            .unwrap()
            .clone()
            .into_ir_def(&iterator.get_current_instr().unwrap().address),
    );

    // Add all following operations, that are not a target nor a jump to the block
    while let Some((instr, op)) = iterator.next() {
        if jump_targets.contains(&iterator.get_blk_tid_of_current_operation()) {
            return blk;
        }
        if matches!(
            iterator.get_current_op().unwrap().pcode_mnemonic,
            PcodeOperation::JmpType(_)
        ) {
            return blk;
        }
        blk.defs.append(
            &mut iterator
                .get_current_op()
                .unwrap()
                .clone()
                .into_ir_def(&iterator.get_current_instr().unwrap().address),
        );
    }
    // What to do if the sequence ends without a jump?
    blk
}

fn finish_blk(mut blk: Blk, iterator: &mut OpIterator, jump_targets: &HashSet<Tid>) -> Blk {
    // If current operation is a target, add implicit branch to next block
    if jump_targets.contains(&iterator.get_blk_tid_of_current_operation()) {
        let (last_instr, last_op) = iterator.get_last_operation_pair().unwrap();
        blk = add_branch_to_blk(
            blk,
            last_instr.address.clone(),
            last_op.pcode_index,
            iterator.get_blk_tid_of_current_operation(),
        );
        // Here the current operation is not changed, since the operation is not translated and add to block yet.
        return blk;
    }

    if matches!(
        iterator.get_current_op().unwrap().pcode_mnemonic,
        PcodeOperation::JmpType(_)
    ) {
        blk = add_jmp_to_blk(
            blk,
            iterator.get_current_instr().unwrap(),
            iterator.get_current_op().unwrap(),
            iterator.get_next_instr().as_ref(),
        );
        // The current operation is translated. We can move to the next operation.
        iterator.next();
        return blk;
    }
    return blk;
}

fn add_jmp_to_blk(
    mut blk: Blk,
    instr: InstructionSimple,
    op: PcodeOpSimple,
    next_instr: Option<&InstructionSimple>,
) -> Blk {
    let fallthrough_address = instr.get_best_guess_fallthrough_addr(next_instr);
    let targets = op.collect_jmp_targets(
        instr.address.clone(),
        instr.pcode_ops.len() as u64,
        fallthrough_address.clone(),
    );
    match op.pcode_mnemonic {
        PcodeOperation::ExpressionType(_) => {
            panic!("current op is not a jump.")
        }
        PcodeOperation::JmpType(BRANCH) => {
            let branch = op.into_ir_jump(&instr.address, targets[0].clone());
            blk.jmps.push(branch);
        }
        // Add conditional branch and then implicit branch
        PcodeOperation::JmpType(CBRANCH) => {
            let targets = op.collect_jmp_targets(
                instr.address.clone(),
                instr.pcode_ops.len() as u64,
                fallthrough_address.clone(),
            );
            let cbranch = op.into_ir_jump(&instr.address, targets[0].clone());
            let implicit_branch = Term {
                tid: Tid {
                    id: format!("instr_{}_{}_implicit_branch", instr.address, op.pcode_index),
                    address: instr.address.clone(),
                },
                term: Jmp::Branch(targets[1].clone()),
            };
            blk.jmps.push(cbranch);
            blk.jmps.push(implicit_branch);
        }
        PcodeOperation::JmpType(jmp) => todo!(),
    }
    return blk;
}

fn add_branch_to_blk(
    mut blk: Blk,
    jump_instruction_address: String,
    pcode_index_branch_side: u64,
    target_tid: Tid,
) -> Blk {
    let branch = Term {
        tid: Tid {
            id: format!(
                "instr_{}_{}_implicit_jmp",
                jump_instruction_address, pcode_index_branch_side
            ),
            address: jump_instruction_address,
        },
        term: Jmp::Branch(target_tid),
    };
    blk.jmps.push(branch);
    blk
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FunctionSimple {
    pub name: String,
    pub address: String,
    pub blocks: Vec<BlockSimple>,
}

impl FunctionSimple {
    fn into_ir_sub(self, jump_targets: &HashSet<u64>) -> Term<Sub> {
        todo!()
    }
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
