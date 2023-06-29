use crate::{
    ghidra_pcode::pcode_operations::PcodeOperation,
    intermediate_representation::{Jmp, Term, Tid},
    pcode::JmpType,
};

use super::PcodeOpSimple;

impl PcodeOpSimple {
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
