use super::*;

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
}

impl Term<Blk> {
    /// Return a clone of `self` where the given suffix is appended to
    /// the TIDs of all contained terms (the block itself and all `Jmp`s and `Def`s).
    ///
    /// Note that all TIDs of jump targets (direct, indirect and return targets) are left unchanged.
    fn clone_with_tid_suffix(&self, suffix: &str) -> Self {
        let mut cloned_block = self.clone();
        cloned_block.tid = cloned_block.tid.with_id_suffix(suffix);
        for def in cloned_block.term.defs.iter_mut() {
            def.tid = def.tid.clone().with_id_suffix(suffix);
        }
        for jmp in cloned_block.term.jmps.iter_mut() {
            jmp.tid = jmp.tid.clone().with_id_suffix(suffix);
        }
        cloned_block
    }
}

impl Project {
    /// Generate a map from all `Sub`, `Blk`, `Def` and `Jmp` TIDs of the project
    /// to the `Sub` TID in which the term is contained.
    fn generate_tid_to_sub_tid_map(&self) -> HashMap<Tid, Tid> {
        let mut tid_to_sub_map = HashMap::new();
        for sub in self.program.term.subs.values() {
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
        for sub in self.program.term.subs.values() {
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
        for sub in self.program.term.subs.values() {
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
        for sub in self.program.term.subs.values() {
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
        for sub in self.program.term.subs.values_mut() {
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
}

/// Create copies of blocks that are contained in more than one subroutine
/// so that each subroutine has its own unique copy of the block.
///
/// The TIDs of the copied blocks (and the contained `Def` and `Jmp` terms)
/// are appended with the sub TID to ensure that TIDs remain globally unique.
/// Target TIDs of intraprocedural jumps are also adjusted
/// to target the sub-specific copy of a block if the target block was duplicated.
pub fn make_block_to_sub_mapping_unique(project: &mut Project) {
    let tid_to_sub_map = project.generate_tid_to_sub_tid_map();
    let block_tid_to_block_map = project.generate_block_tid_to_block_term_map();
    let sub_to_blocks_map =
        project.generate_sub_tid_to_contained_block_tids_map(&block_tid_to_block_map);

    let mut sub_to_additional_blocks_map = project.duplicate_blocks_contained_in_several_subs(
        &sub_to_blocks_map,
        &tid_to_sub_map,
        &block_tid_to_block_map,
    );
    // Add the new blocks to the subs
    for sub in project.program.term.subs.values_mut() {
        sub.term
            .blocks
            .append(&mut sub_to_additional_blocks_map.remove(&sub.tid).unwrap());
    }
    // Intraprocedural jumps need to be adjusted so that they target the sub-specific duplicates.
    project.append_jump_targets_with_sub_suffix_when_target_block_was_duplicated(&tid_to_sub_map);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;

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
                calling_convention: None,
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
        let sub_1_tid = &sub_1.tid;
        let sub_2_tid = &sub_2.tid;
        let sub_3_tid = &sub_3.tid;
        let mut project = Project::mock_empty();
        project.program.term.subs = BTreeMap::from_iter([
            (sub_1_tid.clone(), sub_1.clone()),
            (sub_2_tid.clone(), sub_2.clone()),
            (sub_3.tid.clone(), sub_3.clone()),
        ]);

        make_block_to_sub_mapping_unique(&mut project);

        assert_eq!(&project.program.term.subs[sub_1_tid], &sub_1);
        let sub_2_modified = create_sub_with_blocks(
            "sub_2",
            vec![
                create_block_with_jump_target("blk_3", "blk_2_sub_2"),
                create_block_with_jump_target("blk_2_sub_2", "blk_1_sub_2"),
                create_block_with_jump_target("blk_1_sub_2", "blk_2_sub_2"),
            ],
        );
        assert_eq!(project.program.term.subs[sub_2_tid].term.blocks.len(), 3);
        assert_eq!(
            &project.program.term.subs[sub_2_tid].term.blocks[0],
            &sub_2_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[sub_2_tid]
            .term
            .blocks
            .contains(&sub_2_modified.term.blocks[1]));
        assert!(project.program.term.subs[sub_2_tid]
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
        assert_eq!(project.program.term.subs[sub_3_tid].term.blocks.len(), 4);
        assert_eq!(
            &project.program.term.subs[sub_3_tid].term.blocks[0],
            &sub_3_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[0]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[1]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[2]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[3]));
    }
}
