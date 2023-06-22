use super::*;
use crate::utils::log::LogMessage;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Contains implementation of the block duplication normalization pass.
mod block_duplication_normalization;
use block_duplication_normalization::*;
/// Contains implementation of the propagate control flow normalization pass.
mod propagate_control_flow;
use propagate_control_flow::*;

/// The `Project` struct is the main data structure representing a binary.
///
/// It contains information about the disassembled binary
/// and about the execution environment of the binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Project {
    /// All (known) executable code of the binary is contained in the `program` term.
    pub program: Term<Program>,
    /// The CPU architecture on which the binary is assumed to be executed.
    pub cpu_architecture: String,
    /// The stack pointer register for the given CPU architecture.
    pub stack_pointer_register: Variable,
    /// The known calling conventions that may be used for calls to extern functions.
    pub calling_conventions: BTreeMap<String, CallingConvention>,
    /// The set of all known physical registers for the CPU architecture.
    /// Does only contain base registers, i.e. sub registers of other registers are not contained.
    pub register_set: BTreeSet<Variable>,
    /// Contains the properties of C data types. (e.g. size)
    pub datatype_properties: DatatypeProperties,
    /// Represents the memory after loading the binary.
    pub runtime_memory_image: RuntimeMemoryImage,
}

impl Project {
    /// Return the size (in bytes) for pointers of the given architecture.
    pub fn get_pointer_bytesize(&self) -> ByteSize {
        self.stack_pointer_register.size
    }

    /// Try to guess a standard calling convention from the list of calling conventions in the project.
    pub fn get_standard_calling_convention(&self) -> Option<&CallingConvention> {
        self.calling_conventions
            .get("__stdcall")
            .or_else(|| self.calling_conventions.get("__cdecl"))
            .or_else(|| self.calling_conventions.get("__thiscall")) // for x86_64 Microsoft Windows binaries.
    }

    /// Try to find a specific calling convention in the list of calling conventions in the project.
    /// If not given a calling convention (i.e. given `None`) then falls back to `get_standard_calling_convention`
    pub fn get_specific_calling_convention(
        &self,
        cconv_name_opt: &Option<String>,
    ) -> Option<&CallingConvention> {
        if let Some(cconv_name) = cconv_name_opt {
            self.calling_conventions.get(cconv_name)
        } else {
            self.get_standard_calling_convention()
        }
    }

    /// Return the calling convention associated to the given extern symbol.
    /// If the extern symbol has no annotated calling convention
    /// then return the standard calling convention of the project instead.
    ///
    /// This function panics if no suitable calling convention is found.
    pub fn get_calling_convention(&self, extern_symbol: &ExternSymbol) -> &CallingConvention {
        if let Some(cconv_name) = &extern_symbol.calling_convention {
            self.calling_conventions.get(cconv_name).unwrap()
        } else {
            self.get_standard_calling_convention().unwrap()
        }
    }
}

impl Project {
    /// For all expressions contained in the project,
    /// replace trivially computable subexpressions like `a XOR a` with their result.
    fn substitute_trivial_expressions(&mut self) {
        for sub in self.program.term.subs.values_mut() {
            for block in sub.term.blocks.iter_mut() {
                for def in block.term.defs.iter_mut() {
                    match &mut def.term {
                        Def::Assign { value: expr, .. } | Def::Load { address: expr, .. } => {
                            expr.substitute_trivial_operations()
                        }
                        Def::Store { address, value } => {
                            address.substitute_trivial_operations();
                            value.substitute_trivial_operations();
                        }
                    }
                }
                for jmp in block.term.jmps.iter_mut() {
                    match &mut jmp.term {
                        Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                        Jmp::BranchInd(expr)
                        | Jmp::CBranch {
                            condition: expr, ..
                        }
                        | Jmp::CallInd { target: expr, .. }
                        | Jmp::Return(expr) => expr.substitute_trivial_operations(),
                    }
                }
            }
        }
    }

    /// Replace the return-to TID of calls to extern symbols that are marked as non-returning (e.g. `exit(..)`)
    /// with the provided TID of an artificial sink block.
    ///
    /// Returns `true` if at least one return target has been replaced this way.
    fn retarget_calls_to_non_returning_symbols_to_artificial_sink(
        &mut self,
        dummy_blk_tid: &Tid,
    ) -> bool {
        let mut has_at_least_one_jmp_been_retargeted = false;

        for sub in self.program.term.subs.values_mut() {
            for block in sub.term.blocks.iter_mut() {
                for jmp in block.term.jmps.iter_mut() {
                    if let Jmp::Call {
                        target,
                        return_: Some(return_tid),
                    } = &mut jmp.term
                    {
                        if let Some(extern_symbol) = self.program.term.extern_symbols.get(target) {
                            if extern_symbol.no_return {
                                // Call to an extern symbol that does not return.
                                *return_tid = dummy_blk_tid.clone();
                                has_at_least_one_jmp_been_retargeted = true;
                            }
                        }
                    }
                }
            }
        }
        has_at_least_one_jmp_been_retargeted
    }

    /// Replace jumps to nonexisting TIDs with jumps to a dummy target
    /// representing an artificial sink in the control flow graph.
    /// Return a log message for each replaced jump target.
    /// Also retarget the return address of extern symbol calls that are marked as non-returning to the artificial sink.
    ///
    /// Nonexisting jump targets may be generated by the Ghidra backend
    /// if the data at the target address is not a valid assembly instruction.
    #[must_use]
    fn remove_references_to_nonexisting_tids_and_retarget_non_returning_calls(
        &mut self,
    ) -> Vec<LogMessage> {
        // Gather all existing jump targets
        let mut jump_target_tids = HashSet::new();
        for sub in self.program.term.subs.values() {
            jump_target_tids.insert(sub.tid.clone());
            for block in sub.term.blocks.iter() {
                jump_target_tids.insert(block.tid.clone());
            }
        }
        for symbol_tid in self.program.term.extern_symbols.keys() {
            jump_target_tids.insert(symbol_tid.clone());
        }
        // Replace all jumps to non-existing jump targets with jumps to dummy targets
        let dummy_sub_tid = Tid::new("Artificial Sink Sub");
        let dummy_blk_tid = Tid::new("Artificial Sink Block");
        let mut log_messages = Vec::new();
        for sub in self.program.term.subs.values_mut() {
            for block in sub.term.blocks.iter_mut() {
                if let Err(mut logs) =
                    block.remove_nonexisting_indirect_jump_targets(&jump_target_tids)
                {
                    log_messages.append(&mut logs);
                }
                for jmp in block.term.jmps.iter_mut() {
                    if let Err(log_msg) = jmp.retarget_nonexisting_jump_targets_to_dummy_tid(
                        &jump_target_tids,
                        &dummy_sub_tid,
                        &dummy_blk_tid,
                    ) {
                        log_messages.push(log_msg);
                    }
                }
            }
        }
        // Also replace return targets of calls to non-returning extern symbols
        let dummy_blk_needs_to_be_added =
            self.retarget_calls_to_non_returning_symbols_to_artificial_sink(&dummy_blk_tid);
        // If at least one dummy jump was inserted, add the corresponding dummy sub and block to the program.
        if dummy_blk_needs_to_be_added || !log_messages.is_empty() {
            let dummy_sub: Term<Sub> = Term {
                tid: dummy_sub_tid,
                term: Sub {
                    name: "Artificial Sink Sub".to_string(),
                    blocks: vec![Term {
                        tid: dummy_blk_tid,
                        term: Blk {
                            defs: Vec::new(),
                            jmps: Vec::new(),
                            indirect_jmp_targets: Vec::new(),
                        },
                    }],
                    calling_convention: None,
                },
            };
            self.program
                .term
                .subs
                .insert(dummy_sub.tid.clone(), dummy_sub);
        }
        log_messages
    }

    /// Remove blocks, defs and jumps with duplicate TIDs and return log messages on such cases.
    /// Since such cases break the fundamental invariant that each TID is unique,
    /// they result in errors if not removed.
    ///
    /// Note that each case has a bug as a root cause.
    /// This code is only a workaround so that before the corresponding bug is fixed
    /// the rest of the binary can still be analyzed.
    #[must_use]
    fn remove_duplicate_tids(&mut self) -> Vec<LogMessage> {
        let mut known_tids = HashSet::new();
        let mut errors = Vec::new();
        known_tids.insert(self.program.tid.clone());
        for sub in self.program.term.subs.values_mut() {
            if !known_tids.insert(sub.tid.clone()) {
                panic!("Duplicate of TID {} encountered.", sub.tid);
            }
            let mut filtered_blocks = Vec::new();
            for block in &sub.term.blocks {
                if known_tids.insert(block.tid.clone()) {
                    filtered_blocks.push(block.clone());
                } else {
                    errors.push(LogMessage::new_error(&format!(
                        "Removed duplicate of TID {}. This is a bug in the cwe_checker!",
                        block.tid
                    )));
                }
            }
            sub.term.blocks = filtered_blocks;
            for block in sub.term.blocks.iter_mut() {
                let mut filtered_defs = Vec::new();
                let mut filtered_jmps = Vec::new();
                for def in &block.term.defs {
                    if known_tids.insert(def.tid.clone()) {
                        filtered_defs.push(def.clone());
                    } else {
                        errors.push(LogMessage::new_error(&format!(
                            "Removed duplicate of TID {}. This is a Bug in the cwe_checker!",
                            def.tid
                        )));
                    }
                }
                for jmp in &block.term.jmps {
                    if known_tids.insert(jmp.tid.clone()) {
                        filtered_jmps.push(jmp.clone());
                    } else {
                        errors.push(LogMessage::new_error(&format!(
                            "Removed duplicate of TID {}. This is a Bug in the cwe_checker!",
                            jmp.tid
                        )));
                    }
                }
                block.term.defs = filtered_defs;
                block.term.jmps = filtered_jmps;
            }
        }

        errors
    }

    /// Run some normalization passes over the project.
    ///
    /// Passes:
    /// - Remove duplicate TIDs.
    ///   This is a workaround for a bug in the P-Code-Extractor and should be removed once the bug is fixed.
    /// - Replace jumps to nonexisting TIDs with jumps to artificial sink targets in the CFG.
    ///   Also replace return addresses of non-returning external symbols with artificial sink targets.
    /// - Duplicate blocks so that if a block is contained in several functions, each function gets its own unique copy.
    /// - Propagate input expressions along variable assignments.
    /// - Replace trivial expressions like `a XOR a` with their result.
    /// - Remove dead register assignments.
    /// - Propagate the control flow along chains of conditionals with the same condition.
    /// - Substitute bitwise `AND` and `OR` operations with the stack pointer
    ///   in cases where the result is known due to known stack pointer alignment.
    #[must_use]
    pub fn normalize(&mut self) -> Vec<LogMessage> {
        let mut logs = self.remove_duplicate_tids();
        logs.append(
            &mut self.remove_references_to_nonexisting_tids_and_retarget_non_returning_calls(),
        );
        make_block_to_sub_mapping_unique(self);
        crate::analysis::expression_propagation::propagate_input_expression(self);
        self.substitute_trivial_expressions();
        crate::analysis::dead_variable_elimination::remove_dead_var_assignments(self);
        propagate_control_flow(self);
        logs.append(
            crate::analysis::stack_alignment_substitution::substitute_and_on_stackpointer(self)
                .unwrap_or_default()
                .as_mut(),
        );
        logs
    }
}

impl Term<Jmp> {
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
