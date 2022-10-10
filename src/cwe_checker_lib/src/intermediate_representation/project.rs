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

    /// Propagate input expressions along variable assignments.
    ///
    /// The propagation only occurs inside basic blocks
    /// but not across basic block boundaries.
    fn propagate_input_expressions(&mut self) {
        for sub in self.program.term.subs.values_mut() {
            for block in sub.term.blocks.iter_mut() {
                block.merge_def_assignments_to_same_var();
                block.propagate_input_expressions();
            }
        }
    }

    /// Run some normalization passes over the project.
    ///
    /// Passes:
    /// - Replace jumps to nonexisting TIDs with jumps to artificial sink targets in the CFG.
    /// Also replace return addresses of non-returning external symbols with artificial sink targets.
    /// - Duplicate blocks so that if a block is contained in several functions, each function gets its own unique copy.
    /// - Propagate input expressions along variable assignments.
    /// - Replace trivial expressions like `a XOR a` with their result.
    /// - Remove dead register assignments.
    /// - Propagate the control flow along chains of conditionals with the same condition.
    /// - Substitute bitwise `AND` and `OR` operations with the stack pointer
    /// in cases where the result is known due to known stack pointer alignment.
    #[must_use]
    pub fn normalize(&mut self) -> Vec<LogMessage> {
        let mut logs =
            self.remove_references_to_nonexisting_tids_and_retarget_non_returning_calls();
        make_block_to_sub_mapping_unique(self);
        self.propagate_input_expressions();
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

    impl Project {
        /// Returns project with x64 calling convention and mocked program.
        pub fn mock_x64() -> Project {
            let mut none_cconv_register: Vec<Variable> = vec![
                "RAX", "RBX", "RSP", "RBP", "R10", "R11", "R12", "R13", "R14", "R15",
            ]
            .into_iter()
            .map(|name| Variable::mock(name, ByteSize::new(8)))
            .collect();
            let mut integer_register = CallingConvention::mock_x64().integer_parameter_register;
            integer_register.append(&mut none_cconv_register);

            let calling_conventions: BTreeMap<String, CallingConvention> =
                BTreeMap::from([("__stdcall".to_string(), CallingConvention::mock_x64())]);

            Project {
                program: Term {
                    tid: Tid::new("program_tid"),
                    term: Program::mock_x64(),
                },
                cpu_architecture: "x86_64".to_string(),
                stack_pointer_register: Variable::mock("RSP", 8u64),
                calling_conventions,
                register_set: integer_register.iter().cloned().collect(),
                datatype_properties: DatatypeProperties::mock_x64(),
                runtime_memory_image: RuntimeMemoryImage::mock(),
            }
        }

        pub fn mock_arm32() -> Project {
            let none_cconv_4byte_register: Vec<Variable> = vec!["r12", "r14", "r15"]
                .into_iter()
                .map(|name| Variable::mock(name, ByteSize::new(4)))
                .collect();

            let none_cconv_16byte_register: Vec<Variable> = vec![
                "q0", "q1", "q2", "q3", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
            ]
            .into_iter()
            .map(|name| Variable::mock(name, ByteSize::new(16)))
            .collect();

            let callee_saved_register = CallingConvention::mock_arm32().callee_saved_register;

            let integer_register = CallingConvention::mock_arm32()
                .integer_parameter_register
                .into_iter()
                .chain(none_cconv_4byte_register)
                .chain(none_cconv_16byte_register)
                .chain(callee_saved_register);

            Project {
                program: Term {
                    tid: Tid::new("program_tid"),
                    term: Program::mock_arm32(),
                },
                cpu_architecture: "arm32".to_string(),
                stack_pointer_register: Variable::mock("sp", 4u64),
                calling_conventions: BTreeMap::from([(
                    "__stdcall".to_string(),
                    CallingConvention::mock_arm32(),
                )]),
                register_set: integer_register.collect(),
                datatype_properties: DatatypeProperties::mock_arm32(),
                runtime_memory_image: RuntimeMemoryImage::mock(),
            }
        }
    }

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
