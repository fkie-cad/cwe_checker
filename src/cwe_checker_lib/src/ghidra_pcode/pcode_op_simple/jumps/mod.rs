use crate::{
    ghidra_pcode::pcode_operations::PcodeOperation,
    intermediate_representation::{Expression, Jmp, Term, Tid},
    pcode::JmpType,
};

use super::PcodeOpSimple;

/// A jump target is either a pcode operation (pcode relative jump), or another
/// machine code instruction (absolute jump).
pub enum JmpTarget {
    /// Pcode relative jump `(start, n)` from `start` pcode operation index to
    /// to the `n`-th pcode operation index.
    Relative((u64, u64)),
    /// Machine code instruction jump target with absolute address.
    Absolut(u64),
}

impl PcodeOpSimple {
    /// Returns the jump target, if the `PcodeOperation` is a `JmpType` variant.
    ///
    /// The target is either a pcode operation relative target, or an absolute machine instruction target.
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
                return Some(JmpTarget::Absolut(target.try_to_u64().unwrap()));
            } else if let Expression::Const(jmp_offset) = self.input0.into_ir_expr().unwrap() {
                return Some(JmpTarget::Relative((
                    self.pcode_index,
                    jmp_offset.try_to_u64().unwrap(),
                )));
            }
        }
        None
    }

    pub fn create_jump(&self, address: &String) -> Term<Jmp> {
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

    fn extract_target(&self, address: &String) -> Tid {
        // TODO: target Tid.id name convention
        let target = self
            .input0
            .get_ram_address()
            .unwrap()
            .as_string_with_radix(16);
        Tid {
            id: format!("jmp_from_{}_to_{}", address, target),
            address: target,
        }
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
        // Frage offset anders behalden als location?
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
