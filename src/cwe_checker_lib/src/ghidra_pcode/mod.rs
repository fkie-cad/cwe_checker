//! This module defines the interface for parsing ghidra pcode provided by `PcodeExtractor.java`.
//! The JSON representation is parsed and translated into `cwe_checker`'s [intermediate represnetation](crate::intermediate_representation).
//! Additionally, following normalization steps are performed:
//! * implicit load operations are converted into explitict [Def::Load] representation.

use crate::intermediate_representation::*;
use crate::pcode::ExpressionType;
use anyhow::{anyhow, Result};
use itertools::Itertools;
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

    pub fn get_u64_address(&self) -> u64 {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16).unwrap()
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

    /// Translates a Ghidra pcode block into one or more IR blocks.
    ///
    /// This functions covers the splitting of a pcode block, if:
    /// * it contains a jump target
    /// * it contains pcode relative jumps
    ///
    /// In each case, a new, artificial block is added and the corresponding jump is generated.
    fn into_ir_blk(self, jump_targets: &HashSet<u64>) -> Vec<Term<Blk>> {
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
                match op.pcode_mnemonic {
                    // Add Def to current block.
                    PcodeOperation::ExpressionType(_) => {
                        blk.defs.append(&mut op.clone().into_ir_def(&instr.address))
                    }

                    PcodeOperation::JmpType(_) if op.is_pcode_relative_jump() => todo!(),

                    PcodeOperation::JmpType(crate::pcode::JmpType::CBRANCH) => {
                        // Add conditional (not pcode relative) branch to block
                        blk.jmps.push(op.into_ir_jump(&instr.address));
                        // Add implicit branch to following instruction
                        if let Some(next_instr) = instruction_iterator.peek() {
                            let (finalized_blk, new_blk, new_tid) =
                                finalize_blk_with_branch_and_setup_new_blk(
                                    tid,
                                    &mut blk,
                                    instr.address.clone(),
                                    next_instr.address.clone(),
                                );
                            // add finalized block to block list.
                            blocks.push(finalized_blk);
                            // set new block and tid.
                            blk = new_blk;
                            tid = new_tid;
                        } else {
                            // MIPS: Delay slots for C-Jumps. Ghidra verlegt Delay ggf vor, sodas fallthrough ggf. falsch? (alter code lookup)
                            panic!("Jump target to consecutive instruction is not within block's instructions.")
                        }
                    }
                    PcodeOperation::JmpType(jmp) => {
                        // Add potential targets
                        if matches!(
                            jmp,
                            crate::pcode::JmpType::CALLIND | crate::pcode::JmpType::BRANCHIND
                        ) {
                            if let Some(potential_targets) = &instr.potential_targets {
                                blk.indirect_jmp_targets.append(
                                    &mut potential_targets
                                        .iter()
                                        .map(|x| Tid {
                                            id: format!("potential_target_{}", x),
                                            address: x.to_string(),
                                        })
                                        .collect(),
                                );
                            }
                        }
                        blk.jmps.push(op.into_ir_jump(&instr.address));
                        // TODO: Derive next instruction properly
                        let (finalized_blk, new_blk, new_tid) = finalize_blk_and_setup_new_blk(
                            tid,
                            &mut blk,
                            instruction_iterator
                                .peek()
                                .map_or(instr.address.clone() + "++", |x| x.address.clone()),
                        );
                        blocks.push(finalized_blk);
                        blk = new_blk;
                        tid = new_tid;
                    }
                }
                // If **next** instruction is a target, add branch and set up next block.
                if let Some(next_instr) = instruction_iterator.peek() {
                    if jump_targets.contains(&next_instr.get_u64_address()) && !blk.defs.is_empty()
                    {
                        let (finalized_blk, new_blk, new_tid) =
                            finalize_blk_with_branch_and_setup_new_blk(
                                tid,
                                &mut blk,
                                instr.address.clone(),
                                next_instr.address.clone(),
                            );

                        // add finalized block to block list.
                        blocks.push(finalized_blk);

                        // set new block and tid
                        tid = new_tid;
                        blk = new_blk;
                    }
                }
            }

            // TODO: jump targets die nicht existieren (s. IR.normalize()), leere Blöcke übernehmen.
        }

        // Special case: Block ends without jump.
        // If all instructions are processed and current block is not new, add to blocks.
        // TODO: Add branch here?
        if !blk.defs.is_empty() && !blk.jmps.is_empty() {
            blocks.push(Term {
                tid: tid,
                term: blk,
            });
        }

        blocks
    }
}

/// Helper function for wrapping a block within a tid and prepare new empty block with corresponding tid.
fn finalize_blk_and_setup_new_blk(
    blk_tid: Tid,
    blk: &mut Blk,
    next_instruction_address: String,
) -> (Term<Blk>, Blk, Tid) {
    let new_tid = Tid {
        id: format!("artificial_blk_{}", next_instruction_address),
        address: next_instruction_address,
    };
    let new_blk = Blk {
        defs: vec![],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };

    let finalized_blk = Term {
        tid: blk_tid,
        term: blk.clone(),
    };
    (finalized_blk, new_blk, new_tid)
}

/// Adds a `Jmp::Branch` to the block, wrap block in `Term` and returns it with the new and empty target block with its `Tid`.
fn finalize_blk_with_branch_and_setup_new_blk(
    blk_tid: Tid,
    blk: &mut Blk,
    jump_instruction_address: String,
    next_instruction_address: String,
) -> (Term<Blk>, Blk, Tid) {
    let (mut blk_to_branch_from, new_blk, new_tid) =
        finalize_blk_and_setup_new_blk(blk_tid, blk, next_instruction_address);

    let branch = Term {
        tid: Tid {
            id: format!("artificial_jmp"),
            address: jump_instruction_address,
        },
        term: Jmp::Branch(new_tid.clone()),
    };
    blk_to_branch_from.term.jmps.push(branch);

    (blk_to_branch_from, new_blk, new_tid)
}

fn finalize_blk_and_setup_new_blk_for_pcode_jmp(
    instruction: &InstructionSimple,
    pcode_op: &PcodeOpSimple,
    current_instruction_address: &String,
) {
    if let Some(JmpTarget::Relative((jmp_index, target_index))) = pcode_op.get_jump_target() {
        // Check if target is in instruction's pcode operations
        if target_index < instruction.pcode_ops.len().try_into().unwrap() {
            if let PcodeOperation::JmpType(jmp_type) = pcode_op.pcode_mnemonic {
                use crate::pcode::JmpType::*;

                let new_tid = Tid {
                    id: format!(
                        "artificial_blk_{}_{}",
                        current_instruction_address, target_index
                    ),
                    address: current_instruction_address.to_string(),
                };
                let new_blk = Blk {
                    defs: vec![],
                    jmps: vec![],
                    indirect_jmp_targets: vec![],
                };
                let a = match jmp_type {
                    BRANCH => vec![Term {
                        tid: Tid {
                            id: format!(
                                "pcode_relative_branch_{}_{}",
                                current_instruction_address, jmp_index
                            ),
                            address: current_instruction_address.to_string(),
                        },
                        term: Jmp::Branch(new_tid.clone()),
                    }],
                    CALL => vec![Term {
                        tid: Tid {
                            id: format!(
                                "pcode_relative_call_{}_{}",
                                current_instruction_address, pcode_op.pcode_index
                            ),
                            address: current_instruction_address.to_string(),
                        },
                        term: Jmp::Call {
                            target: new_tid.clone(),
                            return_: None,
                        }, // None as return correct?
                    }],
                    CBRANCH => vec![
                        Term {
                            tid: Tid {
                                id: format!(
                                    "pcode_relative_cbranch_{}_{}",
                                    current_instruction_address, pcode_op.pcode_index
                                ),
                                address: current_instruction_address.to_string(),
                            },
                            term: Jmp::CBranch {
                                target: new_tid.clone(),
                                condition: pcode_op
                                    .input2
                                    .as_ref()
                                    .unwrap()
                                    .into_ir_expr()
                                    .unwrap(),
                            },
                        },
                        Term {
                            tid: Tid {
                                id: format!(
                                    "pcode_relative_cbranch_falltrough_{}_{}",
                                    current_instruction_address, pcode_op.pcode_index
                                ),
                                address: current_instruction_address.to_string(),
                            },
                            term: Jmp::Branch(todo!()),
                        },
                    ],
                    _ => todo!(),
                };
            }
        } else {
            todo!()
        }
    }
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
