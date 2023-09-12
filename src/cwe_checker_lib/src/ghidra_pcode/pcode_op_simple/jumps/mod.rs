use crate::{
    ghidra_pcode::pcode_operations::PcodeOperation,
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
            // Pcode definition distinguishes between `location` and `offset`.
            // Note: $(GHIDRA_PATH)/docs/languages/html/pcodedescription.html#cpui_branch
            // Currently, the IR does not distinguishes these cases.
            // We do nothing here.
            match jmp_type {
                BRANCH | CBRANCH | CALL => (),                  // case `location`
                BRANCHIND | CALLIND | CALLOTHER | RETURN => (), // case `offset`
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
                    // TODO: Negative target index, trigger log message here
                    return Some(JmpTarget::Relative((self.pcode_index, 0)));
                }
            }
        }
        None
    }

    /// Returns the translated jump to the provided location.
    ///
    /// Note: Currently, it supports `BRANCH` and `CBRANCH` only.
    pub fn into_ir_jump(&self, address: &String, target: Tid) -> Term<Jmp> {
        if let PcodeOperation::JmpType(jmp) = self.pcode_mnemonic {
            match jmp {
                JmpType::BRANCH => self.create_branch(address, target),
                JmpType::CBRANCH => self.create_cbranch(address, target),
                JmpType::BRANCHIND => todo!(),
                JmpType::CALL => todo!(),
                JmpType::CALLIND => todo!(),
                JmpType::CALLOTHER => todo!(),
                JmpType::RETURN => todo!(),
            }
        } else {
            panic!("Not a jump operation")
        }
    }

    fn create_branch(&self, address: &String, target: Tid) -> Term<Jmp> {
        wrap_in_tid(address, self.pcode_index, Jmp::Branch(target))
    }

    fn create_cbranch(&self, address: &String, target: Tid) -> Term<Jmp> {
        let cbranch = Jmp::CBranch {
            target: target,
            condition: self.input1.as_ref().unwrap().into_ir_expr().unwrap(),
        };
        wrap_in_tid(address, self.pcode_index, cbranch)
    }

    fn create_branch_indirect(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::BranchInd(self.input0.into_ir_expr().unwrap());
        wrap_in_tid(address, self.pcode_index, branch_ind)
    }

    fn create_call(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::Call {
            target: todo!(),
            return_: Some(todo!()),
        };
        wrap_in_tid(address, self.pcode_index, branch_ind)
    }

    fn create_call_indirect(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::CallInd {
            target: todo!(),
            return_: todo!(),
        };
        wrap_in_tid(address, self.pcode_index, branch_ind)
    }

    fn create_call_other(&self, address: &String) -> Term<Jmp> {
        let call_other = Jmp::CallOther {
            description: todo!(),
            return_: todo!(),
        };
        wrap_in_tid(address, self.pcode_index, call_other)
    }

    fn create_return(&self, address: &String) -> Term<Jmp> {
        let _return = Jmp::Return(todo!());
        wrap_in_tid(address, self.pcode_index, _return)
    }
}

/// Helper function to wrap a `Jmp` in a `Tid` with id `instr_<addr>_<pcode_index>`
fn wrap_in_tid(address: &String, pcode_index: u64, jmp: Jmp) -> Term<Jmp> {
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
