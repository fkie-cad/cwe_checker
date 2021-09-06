//! Methods of [`State`] for manipulating abstract IDs.

use super::*;

impl State {
    /// Replace all occurences of old_id with new_id and adjust offsets accordingly.
    /// This is needed to replace stack/caller IDs on call and return instructions.
    ///
    /// **Example:**
    /// Assume the old_id points to offset 0 in the corresponding memory object and the new_id points to offset -32.
    /// Then the offset_adjustment is -32.
    /// The offset_adjustment gets *added* to the base offset in self.memory.ids (so that it points to offset -32 in the memory object),
    /// while it gets *subtracted* from all pointer values (so that they still point to the same spot in the corresponding memory object).
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &ValueDomain,
    ) {
        for register_data in self.register.values_mut() {
            register_data.replace_abstract_id(old_id, new_id, &(-offset_adjustment.clone()));
        }
        self.memory
            .replace_abstract_id(old_id, new_id, offset_adjustment);
        if &self.stack_id == old_id {
            self.stack_id = new_id.clone();
        }
        if self.caller_stack_ids.get(old_id).is_some() {
            self.caller_stack_ids.remove(old_id);
            self.caller_stack_ids.insert(new_id.clone());
        }
        if self.ids_known_to_caller.get(old_id).is_some() {
            self.ids_known_to_caller.remove(old_id);
            self.ids_known_to_caller.insert(new_id.clone());
        }
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs reachable through concrete pointers contained in them to the set of IDs.
    ///
    /// This uses an underapproximation of the referenced IDs of a memory object,
    /// i.e. IDs may be missing if the analysis lost track of the corresponding pointer.
    pub fn add_directly_reachable_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_underapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs contained in them to the set of IDs.
    ///
    /// This uses an overapproximation of the referenced IDs of a memory object,
    /// i.e. for a memory object it may add IDs as possible references
    /// where the corresponding reference is not longer present in the memory object.
    pub fn add_recursively_referenced_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_overapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Recursively remove all `caller_stack_ids` not corresponding to the given caller.
    pub fn remove_other_caller_stack_ids(&mut self, caller_id: &AbstractIdentifier) {
        let mut ids_to_remove = self.caller_stack_ids.clone();
        ids_to_remove.remove(caller_id);
        for register_value in self.register.values_mut() {
            register_value.remove_ids(&ids_to_remove);
            if register_value.is_empty() {
                *register_value = register_value.top();
            }
        }
        self.memory.remove_ids(&ids_to_remove);
        self.caller_stack_ids = BTreeSet::new();
        self.caller_stack_ids.insert(caller_id.clone());
        self.ids_known_to_caller = self
            .ids_known_to_caller
            .difference(&ids_to_remove)
            .cloned()
            .collect();
    }
}
