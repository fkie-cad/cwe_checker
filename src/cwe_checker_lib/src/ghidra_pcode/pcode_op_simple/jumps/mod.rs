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

    pub fn into_ir_jump(&self, address: &String) -> Term<Jmp> {
        if let PcodeOperation::JmpType(a) = self.pcode_mnemonic {
            match a {
                JmpType::BRANCH => self.create_branch(address),
                JmpType::CBRANCH => self.create_cbranch(address),
                JmpType::BRANCHIND => self.create_branch_indirect(address),
                JmpType::CALL => self.create_call(address),
                JmpType::CALLIND => self.create_call_indirect(address),
                JmpType::CALLOTHER => self.create_call_other(address),
                JmpType::RETURN => self.create_return(address),
            }
        } else {
            panic!("Not a jump operation")
        }
    }

    /// Determines the target ad returns corresponding `Tid`.
    ///
    /// Pcode relative targets are prefixed with `artificial`, e.g. artificial_blk_0x100_4.
    /// Absolute targets (RAM located) are not prefixed, e.g. blk_0x0200
    fn extract_target(&self, address: &String) -> Tid {
        let (id, address) = match self.get_jump_target() {
            Some(JmpTarget::Absolute(_)) => {
                (format!("blk_{}", self.input0.id), self.input0.id.clone())
            }
            Some(JmpTarget::Relative((_, target_index))) => (
                format!("artificial_blk_{}_{}", address, target_index),
                address.clone(),
            ),
            None => panic!("Not a jump operation"),
        };
        Tid { id, address }
    }

    fn wrap_in_tid(&self, address: &String, jmp: Jmp) -> Term<Jmp> {
        Term {
            tid: Tid {
                id: format!("instr_{}_{}", address, self.pcode_index),
                address: address.to_string(),
            },
            term: jmp,
        }
    }

    /// Determines, if the jump target is relative to the pcode index of the jump instruction.
    ///
    /// Note: $(GHIDRA_PATH)/docs/languages/html/pcodedescription.html#cpui_branch
    pub fn is_pcode_relative_jump(&self) -> bool {
        match self.input0.address_space.as_str() {
            "const" => true,
            _ => false,
        }
    }

    fn create_branch(&self, address: &String) -> Term<Jmp> {
        self.wrap_in_tid(address, Jmp::Branch(self.extract_target(address)))
    }

    fn create_cbranch(&self, address: &String) -> Term<Jmp> {
        let cbranch = Jmp::CBranch {
            target: self.extract_target(address),
            condition: self.input1.as_ref().unwrap().into_ir_expr().unwrap(),
        };
        self.wrap_in_tid(address, cbranch)
    }

    fn create_branch_indirect(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::BranchInd(self.input0.into_ir_expr().unwrap());
        self.wrap_in_tid(address, branch_ind)
    }

    fn create_call(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::Call {
            target: self.extract_target(address),
            return_: Some(todo!()),
        };
        self.wrap_in_tid(address, branch_ind)
    }

    fn create_call_indirect(&self, address: &String) -> Term<Jmp> {
        let branch_ind = Jmp::CallInd {
            target: todo!(),
            return_: todo!(),
        };
        self.wrap_in_tid(address, branch_ind)
    }

    fn create_call_other(&self, address: &String) -> Term<Jmp> {
        let call_other = Jmp::CallOther {
            description: todo!(),
            return_: todo!(),
        };
        self.wrap_in_tid(address, call_other)
    }

    fn create_return(&self, address: &String) -> Term<Jmp> {
        let _return = Jmp::Return(todo!());
        self.wrap_in_tid(address, _return)
    }
}

#[cfg(test)]
mod tests;
