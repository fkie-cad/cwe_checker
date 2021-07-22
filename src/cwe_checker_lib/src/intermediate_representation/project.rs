use super::{Blk, CallingConvention, DatatypeProperties, Def, Jmp, Program, Sub, Variable};
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::{HashMap, HashSet};

/// The `Project` struct is the main data structure representing a binary.
///
/// It contains information about the disassembled binary
/// and about the execution environment of the binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Project {
    /// All (known) executable code of the binary is contained in the `program` term.
    pub program: Term<Program>,
    /// The CPU architecture on which the binary is assumed to be executed.
    pub cpu_architecture: String,
    /// The stack pointer register for the given CPU architecture.
    pub stack_pointer_register: Variable,
    /// The known calling conventions that may be used for calls to extern functions.
    pub calling_conventions: Vec<CallingConvention>,
    /// A list of all known physical registers for the CPU architecture.
    /// Does only contain base registers, i.e. sub registers of other registers are not contained.
    pub register_list: Vec<Variable>,
    /// Contains the properties of C data types. (e.g. size)
    pub datatype_properties: DatatypeProperties,
}

impl Project {
    /// Return the size (in bytes) for pointers of the given architecture.
    pub fn get_pointer_bytesize(&self) -> ByteSize {
        self.stack_pointer_register.size
    }

    /// Try to guess a standard calling convention from the list of calling conventions in the project.
    pub fn get_standard_calling_convention(&self) -> Option<&CallingConvention> {
        self.calling_conventions
            .iter()
            .find(|cconv| cconv.name == "__stdcall" || cconv.name == "__cdecl")
    }
}

impl Project {
    /// For all expressions contained in the project,
    /// replace trivially computable subexpressions like `a XOR a` with their result.
    fn substitute_trivial_expressions(&mut self) {
        for sub in self.program.term.subs.iter_mut() {
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

    /// Generate a map from all `Sub`, `Blk`, `Def` and `Jmp` TIDs of the project
    /// to the `Sub` TID in which the term is contained.
    fn generate_tid_to_sub_tid_map(&self) -> HashMap<Tid, Tid> {
        let mut tid_to_sub_map = HashMap::new();
        for sub in self.program.term.subs.iter() {
            tid_to_sub_map.insert(sub.tid.clone(), sub.tid.clone());
            for block in sub.term.blocks.iter() {
                tid_to_sub_map.insert(block.tid.clone(), sub.tid.clone());
                for def in block.term.defs.iter() {
                    tid_to_sub_map.insert(def.tid.clone(), sub.tid.clone());
                }
                for jmp in block.term.jmps.iter() {
                    tid_to_sub_map.insert(jmp.tid.clone(), sub.tid.clone());
                }
            }
        }
        tid_to_sub_map
    }

    /// Generate a map mapping all block TIDs to the corresponding block.
    fn generate_block_tid_to_block_term_map(&self) -> HashMap<Tid, &Term<Blk>> {
        let mut tid_to_block_map = HashMap::new();
        for sub in self.program.term.subs.iter() {
            for block in sub.term.blocks.iter() {
                tid_to_block_map.insert(block.tid.clone(), block);
            }
        }
        tid_to_block_map
    }

    /// Generate a map from all `Sub` TIDs to the set TIDs of all contained blocks in the `Sub`.
    /// Used for the [`Project::make_block_to_sub_mapping_unique`] normalization pass,
    /// as this function assumes that there may exist blocks contained in more than one `Sub`.
    fn generate_sub_tid_to_contained_block_tids_map(
        &self,
        block_tid_to_block_map: &HashMap<Tid, &Term<Blk>>,
    ) -> HashMap<Tid, HashSet<Tid>> {
        let mut sub_to_blocks_map = HashMap::new();
        for sub in self.program.term.subs.iter() {
            let mut worklist: Vec<Tid> =
                sub.term.blocks.iter().map(|blk| blk.tid.clone()).collect();
            let mut block_set = HashSet::new();
            while let Some(block_tid) = worklist.pop() {
                if block_set.get(&block_tid).is_none() {
                    block_set.insert(block_tid.clone());

                    if let Some(block) = block_tid_to_block_map.get(&block_tid) {
                        for jmp in block.term.jmps.iter() {
                            if let Some(tid) = jmp.get_intraprocedural_target_or_return_block_tid()
                            {
                                if block_set.get(&tid).is_none() {
                                    worklist.push(tid);
                                }
                            }
                        }
                        for target_tid in block.term.indirect_jmp_targets.iter() {
                            if block_set.get(target_tid).is_none() {
                                worklist.push(target_tid.clone())
                            }
                        }
                    }
                }
            }
            sub_to_blocks_map.insert(sub.tid.clone(), block_set);
        }
        sub_to_blocks_map
    }

    /// Create duplicates of blocks that are contained in several subfunctions.
    ///
    /// The TIDs of the newly created blocks and the contained Defs and Jmps are appended
    /// with the TID of the sub they are contained in
    /// (to ensure that the newly created terms have unique TIDs).
    /// The TIDs of jump and return targets are not adjusted in this function.
    /// The returned map maps the TID of a `Sub` to the newly created blocks for that `Sub`.
    ///
    /// This function is part of the [`Project::make_block_to_sub_mapping_unique`] normalization pass
    /// and should not be used for other purposes.
    fn duplicate_blocks_contained_in_several_subs(
        &self,
        sub_to_blocks_map: &HashMap<Tid, HashSet<Tid>>,
        tid_to_sub_map: &HashMap<Tid, Tid>,
        block_tid_to_block_map: &HashMap<Tid, &Term<Blk>>,
    ) -> HashMap<Tid, Vec<Term<Blk>>> {
        // Generate new blocks without adjusting jump TIDs
        let mut sub_to_additional_blocks_map = HashMap::new();
        for sub in self.program.term.subs.iter() {
            let tid_suffix = format!("_{}", sub.tid);
            let mut additional_blocks = Vec::new();
            for block_tid in sub_to_blocks_map.get(&sub.tid).unwrap() {
                if tid_to_sub_map.get(block_tid) != Some(&sub.tid) {
                    let block = block_tid_to_block_map
                        .get(block_tid)
                        .unwrap()
                        .clone_with_tid_suffix(&tid_suffix);
                    additional_blocks.push(block);
                }
            }
            sub_to_additional_blocks_map.insert(sub.tid.clone(), additional_blocks);
        }
        sub_to_additional_blocks_map
    }

    /// Appends the `Sub` TID to targets of intraprocedural jumps
    /// if the target block was duplicated by the [`Project::duplicate_blocks_contained_in_several_subs`] function,
    /// so that the jumps target the correct blocks again.
    ///
    /// This function is part of the [`Project::make_block_to_sub_mapping_unique`] normalization pass
    /// and should not be used for other purposes.
    fn append_jump_targets_with_sub_suffix_when_target_block_was_duplicated(
        &mut self,
        tid_to_original_sub_map: &HashMap<Tid, Tid>,
    ) {
        for sub in self.program.term.subs.iter_mut() {
            let tid_suffix = format!("_{}", sub.tid);
            for block in sub.term.blocks.iter_mut() {
                for jump in block.term.jmps.iter_mut() {
                    match &mut jump.term {
                        Jmp::BranchInd(_) | Jmp::Return(_) => (),
                        Jmp::Branch(target) | Jmp::CBranch { target, .. } => {
                            if tid_to_original_sub_map.get(target) != Some(&sub.tid) {
                                *target = target.clone().with_id_suffix(&tid_suffix);
                            }
                        }
                        Jmp::Call { return_, .. }
                        | Jmp::CallInd { return_, .. }
                        | Jmp::CallOther { return_, .. } => {
                            if let Some(target) = return_ {
                                if tid_to_original_sub_map.get(target) != Some(&sub.tid) {
                                    *target = target.clone().with_id_suffix(&tid_suffix);
                                }
                            }
                        }
                    }
                }
                for target in block.term.indirect_jmp_targets.iter_mut() {
                    if tid_to_original_sub_map.get(target) != Some(&sub.tid) {
                        *target = target.clone().with_id_suffix(&tid_suffix);
                    }
                }
            }
        }
    }

    /// Create copies of blocks that are contained in more than one subroutine
    /// so that each subroutine has its own unique copy of the block.
    ///
    /// The TIDs of the copied blocks (and the contained `Def` and `Jmp` terms)
    /// are appended with the sub TID to ensure that TIDs remain globally unique.
    /// Target TIDs of intraprocedural jumps are also adjusted
    /// to target the sub-specific copy of a block if the target block was duplicated.
    fn make_block_to_sub_mapping_unique(&mut self) {
        let tid_to_sub_map = self.generate_tid_to_sub_tid_map();
        let block_tid_to_block_map = self.generate_block_tid_to_block_term_map();
        let sub_to_blocks_map =
            self.generate_sub_tid_to_contained_block_tids_map(&block_tid_to_block_map);

        let mut sub_to_additional_blocks_map = self.duplicate_blocks_contained_in_several_subs(
            &sub_to_blocks_map,
            &tid_to_sub_map,
            &block_tid_to_block_map,
        );
        // Add the new blocks to the subs
        for sub in self.program.term.subs.iter_mut() {
            sub.term
                .blocks
                .append(&mut sub_to_additional_blocks_map.remove(&sub.tid).unwrap());
        }
        // Intraprocedural jumps need to be adjusted so that they target the sub-specific duplicates.
        self.append_jump_targets_with_sub_suffix_when_target_block_was_duplicated(&tid_to_sub_map);
    }

    /// Replace jumps to nonexisting TIDs with jumps to a dummy target
    /// representing an artificial sink in the control flow graph.
    /// Return a log message for each replaced jump target.
    ///
    /// Nonexisting jump targets may be generated by the Ghidra backend
    /// if the data at the target address is not a valid assembly instruction.
    #[must_use]
    fn remove_references_to_nonexisting_tids(&mut self) -> Vec<LogMessage> {
        // Gather all existing jump targets
        let mut jump_target_tids = HashSet::new();
        for sub in self.program.term.subs.iter() {
            jump_target_tids.insert(sub.tid.clone());
            for block in sub.term.blocks.iter() {
                jump_target_tids.insert(block.tid.clone());
            }
        }
        for symbol in self.program.term.extern_symbols.iter() {
            jump_target_tids.insert(symbol.tid.clone());
        }
        // Replace all jumps to non-existing jump targets with jumps to dummy targets
        let dummy_sub_tid = Tid::new("Artificial Sink Sub");
        let dummy_blk_tid = Tid::new("Artificial Sink Block");
        let mut log_messages = Vec::new();
        for sub in self.program.term.subs.iter_mut() {
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
        // If at least one dummy jump was inserted, add the corresponding dummy sub and block to the program.
        if !log_messages.is_empty() {
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
                },
            };
            self.program.term.subs.push(dummy_sub);
        }
        log_messages
    }

    /// Propagate input expressions along variable assignments.
    ///
    /// The propagation only occurs inside basic blocks
    /// but not across basic block boundaries.
    fn propagate_input_expressions(&mut self) {
        for sub in self.program.term.subs.iter_mut() {
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
    /// - Duplicate blocks so that if a block is contained in several functions, each function gets its own unique copy.
    /// - Propagate input expressions along variable assignments.
    /// - Replace trivial expressions like `a XOR a` with their result.
    /// - Remove dead register assignments
    #[must_use]
    pub fn normalize(&mut self) -> Vec<LogMessage> {
        let logs = self.remove_references_to_nonexisting_tids();
        self.make_block_to_sub_mapping_unique();
        self.propagate_input_expressions();
        self.substitute_trivial_expressions();
        crate::analysis::dead_variable_elimination::remove_dead_var_assignments(self);
        logs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Project {
        pub fn mock_empty() -> Project {
            let register_list = vec!["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
                .into_iter()
                .map(|name| Variable::mock(name, ByteSize::new(8)))
                .collect();
            Project {
                program: Term {
                    tid: Tid::new("program_tid"),
                    term: Program::mock_empty(),
                },
                cpu_architecture: "x86_64".to_string(),
                stack_pointer_register: Variable::mock("RSP", 8u64),
                calling_conventions: Vec::new(),
                register_list,
                datatype_properties: DatatypeProperties::mock(),
            }
        }
    }

    fn create_block_with_jump_target(block_name: &str, target_name: &str) -> Term<Blk> {
        Term {
            tid: Tid::new(block_name),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![Term {
                    tid: Tid::new(format!("jmp_{}", block_name)),
                    term: Jmp::Branch(Tid::new(target_name)),
                }],
                indirect_jmp_targets: Vec::new(),
            },
        }
    }

    fn create_sub_with_blocks(sub_name: &str, blocks: Vec<Term<Blk>>) -> Term<Sub> {
        Term {
            tid: Tid::new(sub_name),
            term: Sub {
                name: sub_name.to_string(),
                blocks,
            },
        }
    }

    #[test]
    fn duplication_of_blocks_contained_in_several_subs() {
        let sub_1 = create_sub_with_blocks(
            "sub_1",
            vec![
                create_block_with_jump_target("blk_1", "blk_2"),
                create_block_with_jump_target("blk_2", "blk_1"),
            ],
        );
        let sub_2 = create_sub_with_blocks(
            "sub_2",
            vec![create_block_with_jump_target("blk_3", "blk_2")],
        );
        let sub_3 = create_sub_with_blocks(
            "sub_3",
            vec![create_block_with_jump_target("blk_4", "blk_3")],
        );
        let mut project = Project::mock_empty();
        project.program.term.subs = vec![sub_1.clone(), sub_2, sub_3];

        project.make_block_to_sub_mapping_unique();

        assert_eq!(&project.program.term.subs[0], &sub_1);
        let sub_2_modified = create_sub_with_blocks(
            "sub_2",
            vec![
                create_block_with_jump_target("blk_3", "blk_2_sub_2"),
                create_block_with_jump_target("blk_2_sub_2", "blk_1_sub_2"),
                create_block_with_jump_target("blk_1_sub_2", "blk_2_sub_2"),
            ],
        );
        assert_eq!(project.program.term.subs[1].term.blocks.len(), 3);
        assert_eq!(
            &project.program.term.subs[1].term.blocks[0],
            &sub_2_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[1]
            .term
            .blocks
            .contains(&sub_2_modified.term.blocks[1]));
        assert!(project.program.term.subs[1]
            .term
            .blocks
            .contains(&sub_2_modified.term.blocks[2]));
        let sub_3_modified = create_sub_with_blocks(
            "sub_3",
            vec![
                create_block_with_jump_target("blk_4", "blk_3_sub_3"),
                create_block_with_jump_target("blk_3_sub_3", "blk_2_sub_3"),
                create_block_with_jump_target("blk_2_sub_3", "blk_1_sub_3"),
                create_block_with_jump_target("blk_1_sub_3", "blk_2_sub_3"),
            ],
        );
        assert_eq!(project.program.term.subs[2].term.blocks.len(), 4);
        assert_eq!(
            &project.program.term.subs[2].term.blocks[0],
            &sub_3_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[2]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[0]));
        assert!(project.program.term.subs[2]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[1]));
        assert!(project.program.term.subs[2]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[2]));
        assert!(project.program.term.subs[2]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[3]));
    }
}
