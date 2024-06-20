use super::PcodeOp;
use crate::pcode::JmpType::*;
use crate::{
    ghidra_pcode::{
        block::generate_block_tid, function::generate_placeholder_function_tid,
        instruction::Instruction, pcode_operations::PcodeOperation,
    },
    intermediate_representation::{Expression, Jmp, Term, Tid},
    pcode::JmpType,
};

impl PcodeOp {
    /// Helper function to unwrap the jump type of a P-Code-operation.
    /// Panics if `self` is not a jump.
    fn unwrap_jmp_type(&self) -> &JmpType {
        if let PcodeOperation::JmpType(jmp_type) = &self.pcode_mnemonic {
            jmp_type
        } else {
            panic!("Jump type expected.")
        }
    }

    /// Get the direct jump target of a BRANCH/CBRANCH/CALL instruction as a block TID (even in the case of a CALL).
    /// Panics for other jump types.
    fn get_direct_jump_target(&self, instr: &Instruction) -> Tid {
        match self.unwrap_jmp_type() {
            BRANCH | CBRANCH | CALL => (),
            BRANCHIND | CALLIND | CALLOTHER | RETURN => panic!("Expected BRANCH/CBRANCH/CALL."),
        }
        if let Some(target) = self.input0.get_ram_address_as_string() {
            generate_block_tid(target.to_string(), 0)
        } else if let Expression::Const(jmp_offset) = self.input0.into_ir_expr().unwrap() {
            if let Some(target_index) = self
                .pcode_index
                .checked_add_signed(jmp_offset.try_to_i64().unwrap())
            {
                if target_index >= (instr.pcode_ops().len() as u64) {
                    generate_block_tid(
                        instr
                            .fall_through()
                            .as_deref()
                            .expect("No target found for direct jump.")
                            .to_string(),
                        0,
                    )
                } else {
                    generate_block_tid(instr.address().clone(), target_index)
                }
            } else {
                generate_block_tid(instr.address().clone(), 0)
            }
        } else {
            panic!("Could not parse direct jump target.")
        }
    }

    /// Returns the block TIDs of jump targets, including target hints for indirect calls and branches.
    /// Note that the generated TIDs are always block TIDs, even for call instructions.
    pub fn collect_jmp_targets(&self, instr: &Instruction) -> Vec<Tid> {
        match self.unwrap_jmp_type() {
            BRANCH | CBRANCH | CALL => vec![self.get_direct_jump_target(instr)],
            BRANCHIND | CALLIND => {
                let mut jump_targets = vec![];
                for targets in instr.potential_targets().iter() {
                    for target in targets.iter() {
                        jump_targets.push(generate_block_tid(target.clone(), 0));
                    }
                }
                jump_targets
            }
            CALLOTHER | RETURN => Vec::new(),
        }
    }

    /// Get the fall-through address of the jump instruction, if it has one.
    pub fn get_fall_through_target(&self, instr: &Instruction) -> Option<Tid> {
        let jmp_type = self.unwrap_jmp_type();
        match jmp_type {
            BRANCH | BRANCHIND | RETURN => None,
            CALL | CALLIND => {
                if self.pcode_index + 1 < (instr.pcode_ops().len() as u64) {
                    match instr.pcode_ops()[(self.pcode_index + 1) as usize].pcode_mnemonic {
                        PcodeOperation::JmpType(RETURN) => Some(generate_block_tid(
                            instr.address().clone(),
                            self.pcode_index + 1,
                        )),
                        _ => panic!("Call was not last P-Code-operation of assembly instruction."),
                    }
                } else {
                    instr.fall_through().as_deref().map(|fall_through_addr| {
                        generate_block_tid(fall_through_addr.to_string(), 0)
                    })
                }
            }
            CBRANCH | CALLOTHER => {
                if self.pcode_index + 1 < (instr.pcode_ops().len() as u64) {
                    Some(generate_block_tid(
                        instr.address().clone(),
                        self.pcode_index + 1,
                    ))
                } else {
                    instr.fall_through().as_deref().map(|fall_through_addr| {
                        generate_block_tid(fall_through_addr.to_string(), 0)
                    })
                }
            }
        }
    }

    /// Returns the translated jump to the provided location.
    pub fn into_ir_jump(&self, instr: &Instruction) -> Term<Jmp> {
        let jump = if let PcodeOperation::JmpType(jmp) = self.pcode_mnemonic {
            match jmp {
                JmpType::BRANCH => self.create_branch(self.get_direct_jump_target(instr)),
                JmpType::CBRANCH => self.create_cbranch(self.get_direct_jump_target(instr)),
                JmpType::BRANCHIND => self.create_branch_indirect(),
                JmpType::CALL => self.create_call(instr),
                JmpType::CALLIND => self.create_call_indirect(instr),
                JmpType::CALLOTHER => self.create_call_other(instr),
                JmpType::RETURN => self.create_return(),
            }
        } else {
            panic!("Not a jump operation")
        };
        wrap_in_tid(&instr.address(), self.pcode_index, jump)
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
    fn create_call(&self, instr: &Instruction) -> Jmp {
        Jmp::Call {
            target: generate_placeholder_function_tid(
                self.input0.get_ram_address_as_string().unwrap(),
            ),
            return_: self.get_fall_through_target(instr),
        }
    }

    /// Create an indirect call.
    fn create_call_indirect(&self, instr: &Instruction) -> Jmp {
        Jmp::CallInd {
            target: self.input0.into_ir_expr().unwrap(),
            return_: self.get_fall_through_target(instr),
        }
    }

    /// Create a `CallOther` instruction.
    /// The description is given by the mnemonic of the corresponding assembly instruction
    fn create_call_other(&self, instr: &Instruction) -> Jmp {
        // FIXME: The description shown by Ghidra is actually not the mnemonic!
        // But it is unclear how one can access the description through Ghidras API.
        // Furthermore, we do not encode the optional input varnodes that Ghidra allows for CALLOTHER operations.
        Jmp::CallOther {
            description: instr.mnemonic().clone(),
            return_: self.get_fall_through_target(instr),
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
