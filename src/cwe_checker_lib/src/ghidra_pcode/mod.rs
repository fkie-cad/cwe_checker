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
    fn into_ir_def(self) {
        let mut ops = vec![];
        for mut op in self.pcode_ops {
            ops.append(&mut op.into_ir_def(&self.address))
        }
    }

    /// Returns the instruction field as `u64`.
    pub fn get_u64_address(&self) -> u64 {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16).unwrap()
    }

    pub fn get_u64_falltrough_address(&self) -> Option<u64> {
        match &self.fall_through {
            Some(fallthrough) => {
                Some(u64::from_str_radix(&fallthrough.trim_start_matches("0x"), 16).unwrap())
            }
            None => None,
        }
    }

    /// Determines if a pcode relative jump exceeds the amount of the instructions's pcode operations.
    ///
    /// If the pcode relative jump's target is within the array of the instruction's pcode operations,
    /// `false` is returned. If the jump exceeds te amount of pcode operations, `true` is returned,
    fn contains_relative_jump_to_next_instruction(&self) -> bool {
        for op in &self.pcode_ops {
            if op.is_pcode_relative_jump() {
                if let Some(JmpTarget::Relative((_, target_index))) = op.get_jump_target() {
                    if target_index >= self.pcode_ops.len() as u64 {
                        return true;
                    }
                }
            }
        }

        false
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
    /// a pcode sequence adn the index is larger 0, `_<pcode_index>` is suffixed.
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BlockSimple {
    pub address: String,
    pub instructions: Vec<InstructionSimple>,
}

impl BlockSimple {
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

    /// Translates a Ghidra pcode block into one or more IR blocks.
    ///
    /// This functions covers the splitting of a Ghidra's pcode block, if:
    /// * it contains a jump target
    /// * it contains pcode relative jumps
    ///
    /// In each case, a new, artificial block is added and the corresponding jump is generated.
    fn into_ir_blk(self, jump_targets: &HashSet<Tid>) -> Vec<Term<Blk>> {
        let mut blocks: Vec<Term<Blk>> = vec![];
        // Create first block and its tid
        let mut blk = Blk {
            defs: vec![],
            jmps: vec![],
            indirect_jmp_targets: vec![],
        };
        let mut tid = Tid {
            id: format!("blk_{}", self.address),
            address: self.address,
        };

        // Empty block case
        if self.instructions.is_empty() {
            blocks.push(Term { tid, term: blk });
            return blocks;
        }

        let mut instruction_iterator = self.instructions.iter().peekable();

        while let Some(instr) = instruction_iterator.next() {
            let mut pcode_op_iterator = instr.pcode_ops.iter().peekable();

            while let Some(op) = pcode_op_iterator.next() {
                let fallthrough_address =
                    instr.get_best_guess_fallthrough_addr(instruction_iterator.peek().copied());
                if let Some(finalized_blk) =
                    add_operation_to_blk(op, instr, &mut blk, &mut tid, fallthrough_address)
                {
                    blocks.push(finalized_blk);
                }

                // If next **operation** is a target, finalize current block and set up new block.
                if let Some(consecutive_operation) = pcode_op_iterator.peek() {
                    let target_tid = Tid {
                        id: format!(
                            "blk_{}_{}",
                            instr.address, consecutive_operation.pcode_index
                        ),
                        address: instr.address.clone(),
                    };
                    if jump_targets.contains(&target_tid) {
                        let finalized_blk = finalize_blk_with_branch(
                            tid,
                            blk,
                            instr.address.clone(),
                            op.pcode_index,
                            target_tid.clone(),
                        );
                        blocks.push(finalized_blk);

                        // setup new tid and block
                        tid = target_tid;
                        blk = Blk {
                            defs: vec![],
                            jmps: vec![],
                            indirect_jmp_targets: vec![],
                        }
                    }
                }
                // If no operations are left and the next **instruction** is a target
                else if let Some(consecutive_instr) = instruction_iterator.peek() {
                    let target_tid = Tid {
                        id: format!("blk_{}", consecutive_instr.address),
                        address: instr.address.clone(),
                    };
                    if jump_targets.contains(&target_tid) {
                        let finalized_blk = finalize_blk_with_branch(
                            tid,
                            blk,
                            instr.address.clone(),
                            op.pcode_index,
                            target_tid.clone(),
                        );
                        blocks.push(finalized_blk);

                        // setup new tid and block
                        tid = target_tid;
                        blk = Blk {
                            defs: vec![],
                            jmps: vec![],
                            indirect_jmp_targets: vec![],
                        }
                    }
                }
            }
        }

        // Special case: Block ends without jump.
        // If all instructions are processed and current block is not new, add to blocks.
        if !blk.defs.is_empty() && !blk.jmps.is_empty() {
            // TODO: Add branch here?
            blocks.push(Term {
                tid: tid,
                term: blk,
            });
        }

        blocks
    }
}

/// Translates a pcode operation and adds it to the basic block.
///
/// `blk` is changed by adding the corresponding operation.
/// If the operation is a jump, the block is wrapped into `Term` together with the tid and returned.
/// This function returns `None`, if the operation is not a jump.
///
/// # Note
/// In the case of `JmpType::BRANCHIND`, the block's potential targets are set accordingly.
/// This might introduce Tids to blocks, that are not existing.
fn add_operation_to_blk(
    op: &PcodeOpSimple,
    instr: &InstructionSimple,
    blk: &mut Blk,
    tid: &Tid,
    fallthrough_address: String,
) -> Option<Term<Blk>> {
    match op.pcode_mnemonic {
        // Add Def to current block.
        PcodeOperation::ExpressionType(_) => {
            blk.defs.append(&mut op.clone().into_ir_def(&instr.address));
            return None;
        }
        // Add conditional branch and then implicit branch
        PcodeOperation::JmpType(crate::pcode::JmpType::CBRANCH) => {
            let targets = op.collect_jmp_targets(
                instr.address.clone(),
                instr.pcode_ops.len() as u64,
                fallthrough_address,
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
            let finalized_block = Term {
                tid: tid.clone(),
                term: blk.clone(),
            };
            return Some(finalized_block);
        }
        PcodeOperation::JmpType(jmp) => todo!(),
    }
}

/// Adds a `Jmp::Branch` with provided target to the block, then wraps block with tid in `Term` and returns it.
fn finalize_blk_with_branch(
    blk_tid: Tid,
    mut blk: Blk,
    jump_instruction_address: String,
    pcode_index_branch_side: u64,
    target_tid: Tid,
) -> Term<Blk> {
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

    Term {
        tid: blk_tid.clone(),
        term: blk.clone(),
    }
}

/// Translates instruction with one or more pcode relative jumps into one or more blocks.
/// Not pcode relative jumps are added as well.
///
/// Artificially added block's tid use not artificial addresses.
// fn process_pcode_relative_jump(
//     blk_tid: &mut Tid,
//     blk: &mut Blk,
//     instruction: InstructionSimple,
//     next_instruction_address: Option<String>,
// ) -> Vec<Term<Blk>> {
//     // collect all target indices for identifying backward branching
//     let mut relative_target_indices = HashMap::new();
//     let mut finalized_blocks = vec![];
//     for op in &instruction.pcode_ops {
//         if op.is_pcode_relative_jump() {
//             if let Some(JmpTarget::Relative((branch_side, target_side))) = op.get_jump_target() {
//                 relative_target_indices.insert(branch_side, target_side);
//             }
//         }
//     }

//     // Used for optimazion of jump redirection
//     let mut empty_first_blk_tid = match blk.defs.is_empty() {
//         true => Some(blk_tid.clone()),
//         false => None,
//     };

//     let mut pcode_op_iterator = instruction.pcode_ops.iter().peekable();

//     // If first operation is a target and the block is not empty, finalize block and set up new one.
//     if relative_target_indices.values().contains(&0) && !blk.defs.is_empty() {
//         // finalize block and set up new one
//         let first_op = pcode_op_iterator.peek().expect("No pcode operations");

//         let (finalized_blk, new_blk, new_tid) = finalize_blk_with_branch_and_setup_new_blk(
//             blk_tid,
//             blk,
//             format!("{}_--", instruction.address),
//             format!("{}_{}", instruction.address, first_op.pcode_index),
//         );
//         finalized_blocks.push(finalized_blk);
//         *blk = new_blk;
//         *blk_tid = new_tid;

//         empty_first_blk_tid = Some(blk_tid.clone());
//     }

//     while let Some(op) = pcode_op_iterator.next() {
//         // Set next following instruction address:
//         // Usually the following pcode operation, but if the last operation is processed, the following instruction is used.
//         let fallthrough_addr = match pcode_op_iterator.peek() {
//             Some(next_op) => Some(format!("{}_{}", instruction.address, next_op.pcode_index)),
//             None => next_instruction_address.clone(),
//         };

//         if let Some(mut finalized_blk) =
//             add_operation_to_blk(&op, &instruction, blk, blk_tid, fallthrough_addr)
//         {
//             // Special case of jump target is not within the instructions pcode operation sequence
//             // We consider the next instruction as jump target.
//             if relative_target_indices.get(&op.pcode_index)
//                 >= Some(&(instruction.pcode_ops.len() as u64))
//             {
//                 let block_jump_amount = finalized_blk.term.jmps.len();
//                 let jump_to_next_instr = match op.pcode_mnemonic {
//                     PcodeOperation::ExpressionType(_) => panic!("Jump side is not a JmpType"),
//                     PcodeOperation::JmpType(jmp) if matches!(jmp, CBRANCH) => {
//                         finalized_blk.term.jmps.get_mut(block_jump_amount - 2)
//                     }
//                     PcodeOperation::JmpType(_) => {
//                         finalized_blk.term.jmps.get_mut(block_jump_amount - 1)
//                     }
//                 }
//                 .expect("Finalized block does not have expected jump");

//                 let address_next_instr = next_instruction_address
//                     .clone()
//                     .expect("Next instruction address not available");
//                 let next_instr_tid = Tid {
//                     id: format!("artificial_blk_{}", address_next_instr),
//                     address: address_next_instr,
//                 };
//                 jump_to_next_instr.term = match &jump_to_next_instr.term{
//                     Jmp::Branch(_) => Jmp::Branch(next_instr_tid),
//                     Jmp::CBranch { target: _, condition } => Jmp::CBranch { target: next_instr_tid, condition: condition.clone() },
//                     Jmp::Call { target: _, return_ } => Jmp::Call { target: next_instr_tid, return_: return_.clone() },
//                     // All other variants should not be in collected jump targets anyway.
//                     _ => panic!("Return, BranchInd, CallInd or CallOther are not affected by pcode relative jumps"),
//                 };
//             } else if relative_target_indices.get(&op.pcode_index) == Some(&0) {
//                 // Special case of jump to the first operation, which is the first def the corresponding block.
//                 // Redirect the jump to the block.
//                 if let Some(first_blk_tid) = &empty_first_blk_tid {
//                     let block_jump_amount = finalized_blk.term.jmps.len();
//                     let jump_to_first_blk = match op.pcode_mnemonic {
//                         PcodeOperation::ExpressionType(_) => panic!("Jump side is not a JmpType"),
//                         PcodeOperation::JmpType(jmp) if matches!(jmp, CBRANCH) => {
//                             finalized_blk.term.jmps.get_mut(block_jump_amount - 2)
//                         }
//                         PcodeOperation::JmpType(_) => {
//                             finalized_blk.term.jmps.get_mut(block_jump_amount - 1)
//                         }
//                     }
//                     .expect("Finalized block does not have expected jump");

//                     jump_to_first_blk.term = match &jump_to_first_blk.term{
//                         Jmp::Branch(_) => Jmp::Branch(first_blk_tid.clone()),
//                         Jmp::CBranch { target: _, condition } => Jmp::CBranch { target: first_blk_tid.clone(), condition: condition.clone() },
//                         Jmp::Call { target: _, return_ } => Jmp::Call { target: first_blk_tid.clone(), return_: return_.clone() },
//                         // All other variants should not be in collected jump targets anyway.
//                         _ => panic!("Return, BranchInd, CallInd or CallOther are not affected by pcode relative jumps"),
//                     };
//                 }
//             }
//             finalized_blocks.push(finalized_blk)
//         } else {
//             // if next op is a jump target, add implicit branch and finalize block.
//             if let Some(next_op) = pcode_op_iterator.peek() {
//                 if relative_target_indices
//                     .values()
//                     .contains(&next_op.pcode_index)
//                 {
//                     let (finalized_blk, new_blk, new_tid) =
//                         finalize_blk_with_branch_and_setup_new_blk(
//                             blk_tid,
//                             blk,
//                             format!("{}_{}", instruction.address, op.pcode_index),
//                             format!("{}_{}", instruction.address, next_op.pcode_index),
//                         );
//                     finalized_blocks.push(finalized_blk);
//                     *blk = new_blk;
//                     *blk_tid = new_tid;
//                 }
//             }
//         }
//     }

//     finalized_blocks
// }

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
