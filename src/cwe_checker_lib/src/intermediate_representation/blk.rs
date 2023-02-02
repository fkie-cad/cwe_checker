use super::*;
use crate::utils::log::LogMessage;
use std::{collections::HashSet, fmt};

/// A basic block is a sequence of `Def` instructions followed by up to two `Jmp` instructions.
///
/// The `Def` instructions represent side-effectful operations that are executed in order when the block is entered.
/// `Def` instructions do not affect the control flow of a program.
///
/// The `Jmp` instructions represent control flow affecting operations.
/// There can only be zero, one or two `Jmp`s:
/// - Zero `Jmp`s indicate that the next execution to be executed could not be discerned.
/// This should only happen on disassembler errors or on dead ends in the control flow graph that were deliberately inserted by the user.
/// - If there is exactly one `Jmp`, it is required to be an unconditional jump.
/// - For two jumps, the first one has to be a conditional jump,
/// where the second unconditional jump is only taken if the condition of the first jump evaluates to false.
///
/// If one of the `Jmp` instructions is an indirect jump,
/// then the `indirect_jmp_targets` is a list of possible jump target addresses for that jump.
/// The list may not be complete and the entries are not guaranteed to be correct.
///
/// Basic blocks are *single entry, single exit*, i.e. a basic block is only entered at the beginning
/// and is only exited by the jump instructions at the end of the block.
/// If a new control flow edge is discovered that would jump to the middle of a basic block,
/// the block structure needs to be updated accordingly.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    /// The `Def` instructions of the basic block in order of execution.
    pub defs: Vec<Term<Def>>,
    /// The `Jmp` instructions of the basic block
    pub jmps: Vec<Term<Jmp>>,
    /// If the basic block contains an indirect jump,
    /// this field contains possible jump target addresses for the jump.
    ///
    /// Note that possible targets of indirect calls are *not* contained,
    /// since the [`Project` normalization passes](Project::normalize) assume
    /// that only intraprocedural jump targets are contained in this field.
    pub indirect_jmp_targets: Vec<Tid>,
}

impl Term<Blk> {
    /// Remove indirect jump target addresses for which no corresponding target block exists.
    /// Return an error message for each removed address.
    pub fn remove_nonexisting_indirect_jump_targets(
        &mut self,
        known_block_tids: &HashSet<Tid>,
    ) -> Result<(), Vec<LogMessage>> {
        let mut logs = Vec::new();
        self.term.indirect_jmp_targets = self
            .term
            .indirect_jmp_targets
            .iter()
            .filter_map(|target| {
                if known_block_tids.get(target).is_some() {
                    Some(target.clone())
                } else {
                    let error_msg =
                        format!("Indirect jump target at {} does not exist", target.address);
                    logs.push(LogMessage::new_error(error_msg).location(self.tid.clone()));
                    None
                }
            })
            .collect();
        if logs.is_empty() {
            Ok(())
        } else {
            Err(logs)
        }
    }
}

impl fmt::Display for Blk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for def in self.defs.iter() {
            writeln!(f, "{}: {}", def.tid, def.term)?;
        }
        for jmp in self.jmps.iter() {
            writeln!(f, "{}: {}", jmp.tid, jmp.term)?;
        }
        Ok(())
    }
}
