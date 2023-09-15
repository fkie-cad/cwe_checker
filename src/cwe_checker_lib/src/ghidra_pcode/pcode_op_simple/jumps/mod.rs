use super::PcodeOpSimple;
use crate::{
    ghidra_pcode::{
        block::generate_block_tid, function::generate_placeholder_function_tid,
        instruction::InstructionSimple, pcode_operations::PcodeOperation,
    },
    intermediate_representation::{Expression, Jmp, Term, Tid},
    pcode::JmpType,
};

/// A jump target is either a pcode operation (pcode relative jump), or another
/// machine code instruction (absolute jump).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum JmpTarget {
    /// Pcode relative jump `(jmp_index, target_index)` from `jmp_index` pcode operation index to
    /// to the `target_index` pcode operation index.
    /// Note that both are indices and **not** offsets.
    Relative((u64, u64)),
    /// Machine code instruction jump target with absolute address.
    Absolute(u64),
}

impl PcodeOpSimple {
    /// Returns the jump target, if the `PcodeOperation` is a `JmpType` variant.
    ///
    /// The target is either a pcode operation relative target, or an absolute machine instruction target.
    /// Relative jumps to indices below 0, are interpreted as jumps to the index 0.
    pub fn get_jump_target(&self) -> Option<JmpTarget> {
        use crate::pcode::JmpType::*;
        if let PcodeOperation::JmpType(jmp_type) = &self.pcode_mnemonic {
            match jmp_type {
                BRANCH | CBRANCH | CALL => (),
                BRANCHIND | CALLIND | CALLOTHER | RETURN => return None,
            }
            if let Some(target) = self.input0.get_ram_address() {
                return Some(JmpTarget::Absolute(target.try_to_u64().unwrap()));
            } else if let Expression::Const(jmp_offset) = self.input0.into_ir_expr().unwrap() {
                if let Some(target_index) = self
                    .pcode_index
                    .checked_add_signed(jmp_offset.try_to_i64().unwrap())
                {
                    return Some(JmpTarget::Relative((self.pcode_index, target_index)));
                } else {
                    return Some(JmpTarget::Relative((self.pcode_index, 0)));
                }
            }
        }
        panic!("operation is not a jump")
    }

    /// Returns the translated jump to the provided location.
    pub fn into_ir_jump(&self, instr: &InstructionSimple) -> Term<Jmp> {
        let address = &instr.address;
        let targets = self.collect_jmp_targets(
            instr.address.clone(),
            instr.pcode_ops.len() as u64,
            instr.fall_through.as_deref(),
        );
        let jump = if let PcodeOperation::JmpType(jmp) = self.pcode_mnemonic {
            match jmp {
                JmpType::BRANCH => self.create_branch(targets[0].clone()),
                JmpType::CBRANCH => self.create_cbranch(targets[0].clone()),
                JmpType::BRANCHIND => self.create_branch_indirect(),
                JmpType::CALL => self.create_call(instr.fall_through.as_deref()),
                JmpType::CALLIND => self.create_call_indirect(instr.fall_through.as_deref()),
                JmpType::CALLOTHER => self.create_call_other(instr),
                JmpType::RETURN => self.create_return(),
            }
        } else {
            panic!("Not a jump operation")
        };
        wrap_in_tid(address, self.pcode_index, jump)
    }

    /// Create a branch instruction.
    fn create_branch(&self, target: Tid) -> Jmp {
        Jmp::Branch(target)
    }

    // Create a conditional branch.
    fn create_cbranch(&self, target: Tid) -> Jmp {
        Jmp::CBranch {
            target,
            condition: self.input1.as_ref().unwrap().into_ir_expr().unwrap(),
        }
    }

    /// Create an indirect branch.
    fn create_branch_indirect(&self) -> Jmp {
        Jmp::BranchInd(self.input0.into_ir_expr().unwrap())
    }

    /// Create a call.
    fn create_call(&self, return_addr: Option<&str>) -> Jmp {
        let return_ = return_addr.map(|address| generate_block_tid(address.to_string(), 0));
        Jmp::Call {
            target: generate_placeholder_function_tid(
                self.input0.get_ram_address_as_string().unwrap(),
            ),
            return_,
        }
    }

    /// Create an indirect call.
    fn create_call_indirect(&self, return_addr: Option<&str>) -> Jmp {
        let return_ = return_addr.map(|address| generate_block_tid(address.to_string(), 0));
        Jmp::CallInd {
            target: self.input0.into_ir_expr().unwrap(),
            return_,
        }
    }

    /// Create a `CallOther` instruction.
    /// The description is given by the mnemonic of the corresponding assembly instruction
    fn create_call_other(&self, instr: &InstructionSimple) -> Jmp {
        // FIXME: The description shown by Ghidra is actually not the mnemonic!
        // But it is unclear how one can access the description through Ghidras API.
        // Furthermore, we do not encode the optional input varnodes that Ghidra allows for CALLOTHER operations.
        let return_ = if (self.pcode_index as usize) < instr.pcode_ops.len() - 1 {
            Some(generate_block_tid(
                instr.address.clone(),
                self.pcode_index + 1,
            ))
        } else {
            instr
                .fall_through
                .as_deref()
                .map(|address| generate_block_tid(address.to_string(), 0))
        };
        Jmp::CallOther {
            description: instr.mnemonic.clone(),
            return_,
        }
    }

    /// Create a return instruction.
    fn create_return(&self) -> Jmp {
        Jmp::Return(self.input0.into_ir_expr().unwrap())
    }
}

/// Helper function to wrap a `Jmp` in a `Tid` with id `instr_<addr>_<pcode_index>`
fn wrap_in_tid(address: &str, pcode_index: u64, jmp: Jmp) -> Term<Jmp> {
    Term {
        tid: Tid {
            id: format!("instr_{}_{}", address, pcode_index),
            address: address.to_string(),
        },
        term: jmp,
    }
}

#[cfg(test)]
mod tests;
