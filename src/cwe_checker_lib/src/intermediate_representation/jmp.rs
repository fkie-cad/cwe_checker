use super::Expression;
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::HashSet;

/// A `Jmp` instruction affects the control flow of a program, i.e. it may change the instruction pointer.
/// With the exception of `CallOther`, it has no other side effects.
///
/// `Jmp` instructions carry some semantic information with it, like whether a jump is intra- or interprocedural.
/// Note that this semantic information may not always be correct.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Jmp {
    /// A direct intraprocedural jump to the targeted `Blk` term identifier.
    Branch(Tid),
    /// An indirect intraprocedural jump to the address that the given expression evaluates to.
    BranchInd(Expression),
    /// A direct intraprocedural jump that is only taken if the condition evaluates to true (i.e. not zero).
    CBranch {
        /// The term ID of the target block of the jump.
        target: Tid,
        /// The jump is only taken if this expression evaluates to `true`, (i.e. not zero).
        condition: Expression,
    },
    /// A direct interprocedural jump representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::Branch`.
    Call {
        /// The term ID of the target subroutine (`Sub`) or extern symbol of the call.
        target: Tid,
        /// The term ID of the block that the called function returns to.
        /// May be `None` if it is assumed that the called function never returns.
        return_: Option<Tid>,
    },
    /// An indirect interprocedural jump to the address the `target` expression evaluates to
    /// and representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::BranchInd`.
    CallInd {
        /// An expression computing the target address of the call.
        target: Expression,
        /// The term ID of the block that the called function returns to.
        /// May be `None` if it is assumed that the called function never returns.
        return_: Option<Tid>,
    },
    /// A indirect interprocedural jump indicating a return from a subroutine.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::BranchInd`.
    Return(Expression),
    /// This instruction is used for all side effects that are not representable by other instructions
    /// or not supported by the disassembler.
    ///
    /// E.g. syscalls and other interrupts are mapped to `CallOther`.
    /// Assembly instructions that the disassembler does not support are also mapped to `CallOther`.
    /// One can use the `description` field to match for and handle known side effects (e.g. syscalls).
    CallOther {
        /// A description of the side effect.
        description: String,
        /// The block term identifier of the block
        /// where the disassembler assumes that execution will continue after handling of the side effect.
        return_: Option<Tid>,
    },
}

impl Term<Jmp> {
    /// If the jump is intraprocedural, return its target TID.
    /// If the jump is a call, return the TID of the return target.
    fn get_intraprocedural_target_or_return_block_tid(&self) -> Option<Tid> {
        match &self.term {
            Jmp::BranchInd(_) | Jmp::Return(_) => None,
            Jmp::Branch(tid) => Some(tid.clone()),
            Jmp::CBranch { target, .. } => Some(target.clone()),
            Jmp::Call { return_, .. }
            | Jmp::CallInd { return_, .. }
            | Jmp::CallOther { return_, .. } => return_.as_ref().cloned(),
        }
    }

    /// If the TID of a jump target or return target is not contained in `known_tids`
    /// replace it with a dummy TID and return an error message.
    fn retarget_nonexisting_jump_targets_to_dummy_tid(
        &mut self,
        known_tids: &HashSet<Tid>,
        dummy_sub_tid: &Tid,
        dummy_blk_tid: &Tid,
    ) -> Result<(), LogMessage> {
        use Jmp::*;
        match &mut self.term {
            BranchInd(_) => (),
            Branch(tid) | CBranch { target: tid, .. } if known_tids.get(tid).is_none() => {
                let error_msg = format!("Jump target at {} does not exist", tid.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *tid = dummy_blk_tid.clone();
                return Err(error_log);
            }
            Call { target, return_ } if known_tids.get(target).is_none() => {
                let error_msg = format!("Call target at {} does not exist", target.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *target = dummy_sub_tid.clone();
                *return_ = None;
                return Err(error_log);
            }
            Call {
                return_: Some(return_tid),
                ..
            }
            | CallInd {
                return_: Some(return_tid),
                ..
            }
            | CallOther {
                return_: Some(return_tid),
                ..
            } if known_tids.get(return_tid).is_none() => {
                let error_msg = format!("Return target at {} does not exist", return_tid.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *return_tid = dummy_blk_tid.clone();
                return Err(error_log);
            }
            _ => (),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retarget_nonexisting_jumps() {
        let mut jmp_term = Term {
            tid: Tid::new("jmp"),
            term: Jmp::Branch(Tid::new("nonexisting_target")),
        };
        assert_eq!(jmp_term.term, Jmp::Branch(Tid::new("nonexisting_target")));
        assert!(jmp_term
            .retarget_nonexisting_jump_targets_to_dummy_tid(
                &HashSet::new(),
                &Tid::new("dummy_sub"),
                &Tid::new("dummy_blk")
            )
            .is_err());
        assert_eq!(jmp_term.term, Jmp::Branch(Tid::new("dummy_blk")));
    }
}
