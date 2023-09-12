use super::InstructionSimple;
use super::PcodeOpSimple;
use super::PcodeOperation;
use crate::intermediate_representation::*;
use crate::pcode::JmpType::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::Peekable;

/// Iterator-like struct for iterating over the P-Code operations contained in a slice of [`InstructionSimple`] objects.
struct OpIterator<'a> {
    /// The iterator over the assembly instructions
    instr_iter: Peekable<std::slice::Iter<'a, InstructionSimple>>,
    /// The iterator over the P-Code instructions contained in the current assembly instruction
    op_iter: Option<Peekable<std::slice::Iter<'a, PcodeOpSimple>>>,
    /// The current assembly instruction
    current_instr: Option<&'a InstructionSimple>,
    /// The list of known jump targets.
    jump_targets: &'a HashSet<Tid>,
}

impl<'a> OpIterator<'a> {
    /// Create a new iterator out of a slice and the list of known jump targets.
    pub fn new(instructions: &'a [InstructionSimple], jump_targets: &'a HashSet<Tid>) -> Self {
        Self {
            instr_iter: instructions.iter().peekable(),
            op_iter: None,
            current_instr: None,
            jump_targets,
        }
    }

    /// Get the next instruction.
    /// Reset the P-code operation iterator accordingly.
    fn next_instr(&mut self) -> Option<&'a InstructionSimple> {
        if let Some(instr) = self.instr_iter.next() {
            self.op_iter = Some(instr.pcode_ops.iter().peekable());
            self.current_instr = Some(instr);
            Some(instr)
        } else {
            self.op_iter = None;
            self.current_instr = None;
            None
        }
    }

    /// Peek the next assembly instruction without advancing the iterator.
    fn peek_next_instr(&mut self) -> Option<&'a InstructionSimple> {
        self.instr_iter.peek().copied()
    }

    /// If the next instruction (either P-Code or assembly instruction) is a jump target,
    /// then return the corresponding block TID
    fn peek_for_jmp_target(&mut self) -> Option<Tid> {
        if let Some(op_iter) = self.op_iter.as_mut() {
            if let Some(op) = op_iter.peek() {
                let address = self.current_instr.unwrap().address.clone();
                let blk_tid_name = match op.pcode_index {
                    0 => format!("blk_{}", address),
                    pcode_index => format!("blk_{}_{}", address, pcode_index),
                };
                let blk_tid = Tid {
                    id: blk_tid_name,
                    address,
                };
                if self.jump_targets.contains(&blk_tid) {
                    return Some(blk_tid);
                }
            }
        }
        if let Some(instr) = self.instr_iter.peek() {
            let blk_tid = Tid {
                id: format!("blk_{}", instr.address),
                address: instr.address.clone(),
            };
            if self.jump_targets.contains(&blk_tid) {
                return Some(blk_tid);
            }
        }
        None
    }

    /// Return `true` if the next P-Code instruction is a jump.
    fn peek_for_jmp_op(&mut self) -> bool {
        if let Some(op_iter) = self.op_iter.as_mut() {
            if let Some(op) = op_iter.peek() {
                match op.pcode_mnemonic {
                    PcodeOperation::JmpType(_) => return true,
                    PcodeOperation::ExpressionType(_) => return false,
                }
            }
        }
        if let Some(instr) = self.instr_iter.peek() {
            if let Some(op) = instr.pcode_ops.first() {
                match op.pcode_mnemonic {
                    PcodeOperation::JmpType(_) => return true,
                    PcodeOperation::ExpressionType(_) => return false,
                }
            }
        }
        false
    }

    /// Peek the address (as a string) and the P-Code-Index of the next instruction (either P-Code or assembly).
    pub fn peek_next_tid(&mut self) -> Option<(&'a str, u64)> {
        if let Some(op_iter) = self.op_iter.as_mut() {
            if let Some(op) = op_iter.peek() {
                return Some((&self.current_instr.unwrap().address, op.pcode_index));
            }
        }
        if let Some(instr) = self.instr_iter.peek() {
            Some((&instr.address, 0))
        } else {
            None
        }
    }

    /// Advance the iterator until one of the following occurs:
    /// - The peeked next instruction would be a jump target not equal to the given block TID. Return None.
    ///   The comparison with the given block TID ensures that Defs are added to blocks starting with a jump target.
    /// - The peeked next instruction is a jump. Return None.
    /// - A P-Code operation corresponding to a `Def` is reached.
    ///   Yield the operation and the address of the corresponding assembly instruction.
    pub fn next_def(&mut self, block_tid: &Tid) -> Option<(&'a PcodeOpSimple, &'a str)> {
        loop {
            if let Some(jmp_target) = self.peek_for_jmp_target().as_ref() {
                if jmp_target != block_tid {
                    return None;
                }
            }
            if self.peek_for_jmp_op() {
                return None;
            }
            if let Some(op_iter) = self.op_iter.as_mut() {
                if let Some(op) = op_iter.next() {
                    return Some((op, &self.current_instr.unwrap().address));
                }
            }
            // Forward to next instruction and repeat the loop
            if self.peek_next_instr().is_none() {
                // We reached the end of the iterator.
                return None;
            }
            self.next_instr();
        }
    }

    /// If the next operation is a jump, yield it together with the address of the corresponding assembly instruction.
    pub fn next_jmp(&mut self) -> Option<(&'a PcodeOpSimple, &'a str)> {
        if !self.peek_for_jmp_op() {
            return None;
        }
        if let Some(op_iter) = self.op_iter.as_mut() {
            if let Some(jmp_op) = op_iter.next() {
                return Some((jmp_op, &self.current_instr.unwrap().address));
            }
        }
        self.next_instr().unwrap();
        let op_iter = self.op_iter.as_mut().unwrap();
        let jmp_op = op_iter.next().unwrap();
        Some((jmp_op, &self.current_instr.unwrap().address))
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
    pub fn collect_jmp_targets(&self) -> HashSet<Tid> {
        // Collecting jump targets for splitting up blocks
        let mut jump_targets = HashSet::new();
        let mut instructions = self.instructions.iter().peekable();

        while let Some(instr) = instructions.next() {
            jump_targets.extend(instr.collect_jmp_targets(instructions.peek().copied()))
        }
        jump_targets
    }

    /// Translates a Basic block by Ghidra into one or many IR basic blocks.
    pub fn into_ir_blk(self, jump_targets: &HashSet<Tid>) -> Vec<Term<Blk>> {
        let mut finalized_blocks = vec![];

        // The iterator provides the currently pcode operation together with its instruction.
        let mut iterator = OpIterator::new(&self.instructions[..], jump_targets);

        // While a current operation is present, translate it and add it to a block...
        while let Some((instr_addr, pcode_index)) = iterator.peek_next_tid() {
            let tid = generate_new_tid(instr_addr.to_string(), pcode_index);
            let block = Term {
                tid,
                term: Blk::new(),
            };
            let block = add_defs_to_block(block, &mut iterator);
            let block = add_jump_to_block(block, &mut iterator);
            finalized_blocks.push(block);
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
fn add_defs_to_block(mut block: Term<Blk>, iterator: &mut OpIterator) -> Term<Blk> {
    while let Some((def_op, address)) = iterator.next_def(&block.tid) {
        block
            .term
            .defs
            .append(&mut def_op.clone().into_ir_def(address));
    }
    block
}

/// Create the TID of an implicit jump instruction that gets added to a block
/// when it does not end in a jump in Ghidra but falls through to the next instruction.
fn create_implicit_jmp_tid(block: &Term<Blk>) -> Tid {
    if let Some(last_def) = block.term.defs.last() {
        last_def.tid.clone().with_id_suffix("_implicit_jump")
    } else {
        // FIXME: This generates instructions with a "blk" prefix.
        // Usually, we want to avoid that.
        block.tid.clone().with_id_suffix("_implicit_jump")
    }
}

/// Add jumps to the block depending on the situation:
/// - If the next instruction in the iterator is a jump target, then add a fallthrough jump to that instruction to the block.
/// - Else if the next instruction is a jump, create the corresponding IR-jumps and add them to the block.
/// - Else try to add a fallthrough jump to the next block on a best-effort basis.
fn add_jump_to_block(mut block: Term<Blk>, iterator: &mut OpIterator) -> Term<Blk> {
    if let Some(target_tid) = iterator.peek_for_jmp_target() {
        if target_tid != block.tid {
            // The target is not the very first instruction of the block
            let jmp_tid = create_implicit_jmp_tid(&block);
            let jmp = Term {
                tid: jmp_tid,
                term: Jmp::Branch(target_tid),
            };
            block.term.jmps.push(jmp);
            return block;
        }
    }
    if let Some((jmp_op, _)) = iterator.next_jmp() {
        block.term = add_jmp_to_blk(
            block.term,
            iterator.current_instr.unwrap().clone(),
            jmp_op.clone(),
            iterator.peek_next_instr(),
        );
        return block;
    }
    if let Some(instr) = iterator.current_instr {
        let jmp_tid = create_implicit_jmp_tid(&block);
        let fallthrough_address = instr.get_best_guess_fallthrough_addr(None);
        // TODO: The generation of the TID should not be made by hand here but refactored to somewhere else.
        let target_tid = Tid {
            id: format!("blk_{}", fallthrough_address),
            address: fallthrough_address,
        };
        let jmp = Term {
            tid: jmp_tid,
            term: Jmp::Branch(target_tid),
        };
        block.term.jmps.push(jmp);
        return block;
    }
    // Else we cannot guess a fallthrough address without any instruction and the block ends without a jump.
    block
}

/// Add the given jump operation to the block and, if necessary, a second fallthrough jump instruction.
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
                    id: format!("instr_{}_{}_implicit_jump", instr.address, op.pcode_index),
                    address: instr.address.clone(),
                },
                term: Jmp::Branch(targets[1].clone()),
            };
            blk.jmps.push(cbranch);
            blk.jmps.push(implicit_branch);
        }
        PcodeOperation::JmpType(jmp) => todo!(), // TODO
    }
    return blk;
}

#[cfg(test)]
pub mod tests;