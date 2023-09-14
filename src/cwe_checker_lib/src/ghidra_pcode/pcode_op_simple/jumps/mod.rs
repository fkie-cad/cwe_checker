use crate::{
    ghidra_pcode::{
        block::generate_block_tid, function::generate_placeholder_function_tid,
        instruction::InstructionSimple, pcode_operations::PcodeOperation,
    },
    intermediate_representation::{Expression, Jmp, Term, Tid},
    pcode::JmpType,
};

use super::PcodeOpSimple;

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
                // TODO: The computation for negative target indices does not work for 32-bit-systems,
                // as addition causes no overflow when using u64 for the computation!
                if let Some(target_index) = self
                    .pcode_index
                    .checked_add_signed(jmp_offset.try_to_i64().unwrap())
                {
                    return Some(JmpTarget::Relative((self.pcode_index, target_index)));
                } else {
                    // TODO: Negative target index, trigger log message here
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
        if let PcodeOperation::JmpType(jmp) = self.pcode_mnemonic {
            match jmp {
                JmpType::BRANCH => self.create_branch(address, targets[0].clone()),
                JmpType::CBRANCH => self.create_cbranch(address, targets[0].clone()),
                JmpType::BRANCHIND => self.create_branch_indirect(address),
                JmpType::CALL => self.create_call(address, instr.fall_through.as_deref()),
                JmpType::CALLIND => {
                    self.create_call_indirect(address, instr.fall_through.as_deref())
                }
                JmpType::CALLOTHER => {
                    self.create_call_other(address, &instr.mnemonic, instr.fall_through.as_deref())
                }
                JmpType::RETURN => self.create_return(address),
            }
        } else {
            panic!("Not a jump operation")
        }
    }

    fn create_branch(&self, address: &str, target: Tid) -> Term<Jmp> {
        wrap_in_tid(address, self.pcode_index, Jmp::Branch(target))
    }

    fn create_cbranch(&self, address: &str, target: Tid) -> Term<Jmp> {
        let cbranch = Jmp::CBranch {
            target,
            condition: self.input1.as_ref().unwrap().into_ir_expr().unwrap(),
        };
        wrap_in_tid(address, self.pcode_index, cbranch)
    }

    fn create_branch_indirect(&self, address: &str) -> Term<Jmp> {
        let branch_ind = Jmp::BranchInd(self.input0.into_ir_expr().unwrap());
        wrap_in_tid(address, self.pcode_index, branch_ind)
    }

    fn create_call(&self, address: &str, return_addr: Option<&str>) -> Term<Jmp> {
        let return_ = return_addr.map(|address| generate_block_tid(address.to_string(), 0));
        let call = Jmp::Call {
            target: generate_placeholder_function_tid(
                self.input0.get_ram_address_as_string().unwrap(),
            ),
            return_,
        };
        wrap_in_tid(address, self.pcode_index, call)
    }

    fn create_call_indirect(&self, address: &str, return_addr: Option<&str>) -> Term<Jmp> {
        let return_ = return_addr.map(|address| generate_block_tid(address.to_string(), 0));
        let call_ind = Jmp::CallInd {
            target: self.input0.into_ir_expr().unwrap(),
            return_,
        };
        wrap_in_tid(address, self.pcode_index, call_ind)
    }

    fn create_call_other(
        &self,
        address: &str,
        mnemonic: &str,
        return_addr: Option<&str>,
    ) -> Term<Jmp> {
        let return_ = return_addr.map(|address| generate_block_tid(address.to_string(), 0));
        let call_other = Jmp::CallOther {
            description: mnemonic.to_string(),
            return_,
        };
        wrap_in_tid(address, self.pcode_index, call_other)
    }

    fn create_return(&self, address: &str) -> Term<Jmp> {
        let _return = Jmp::Return(self.input0.into_ir_expr().unwrap());
        wrap_in_tid(address, self.pcode_index, _return)
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
