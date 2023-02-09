use std::fmt;

use super::Expression;
use crate::prelude::*;

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

impl fmt::Display for Jmp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Jmp::Branch(tid) => write!(f, "Jump to {tid}"),
            Jmp::BranchInd(expr) => write!(f, "Jump to {expr}"),
            Jmp::CBranch { target, condition } => write!(f, "If {condition} jump to {target}"),
            Jmp::Call { target, return_ } => write!(
                f,
                "call {} ret {}",
                target,
                return_.as_ref().unwrap_or(&Tid::new("?"))
            ),
            Jmp::CallInd { target, return_ } => write!(
                f,
                "call {} ret {}",
                target,
                return_.as_ref().unwrap_or(&Tid::new("?"))
            ),
            Jmp::Return(expr) => write!(f, "ret {expr}"),
            Jmp::CallOther {
                description,
                return_,
            } => write!(
                f,
                "call {} ret {}",
                description,
                return_.as_ref().unwrap_or(&Tid::new("?"))
            ),
        }
    }
}
