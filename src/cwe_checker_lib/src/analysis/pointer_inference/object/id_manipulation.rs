use super::*;
use std::collections::BTreeMap;

impl AbstractObject {
    /// Get all abstract IDs that the object may contain pointers to.
    /// This yields an overapproximation of possible pointer targets.
    pub fn get_referenced_ids_overapproximation(&self) -> &BTreeSet<AbstractIdentifier> {
        &self.inner.pointer_targets
    }

    /// Get all abstract IDs for which the object contains pointers to.
    /// This yields an underapproximation of pointer targets,
    /// since the object may contain pointers that could not be tracked by the analysis.
    pub fn get_referenced_ids_underapproximation(&self) -> BTreeSet<AbstractIdentifier> {
        let mut referenced_ids = BTreeSet::new();
        for data in self.inner.memory.values() {
            referenced_ids.extend(data.referenced_ids().cloned())
        }
        referenced_ids
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offsets.
    /// This is needed to adjust stack pointers on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &ValueDomain,
    ) {
        let inner = Arc::make_mut(&mut self.inner);
        for elem in inner.memory.values_mut() {
            elem.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        inner.memory.clear_top_values();
        if inner.pointer_targets.get(old_id).is_some() {
            inner.pointer_targets.remove(old_id);
            inner.pointer_targets.insert(new_id.clone());
        }
    }

    /// Remove the provided IDs from the target lists of all pointers in the memory object.
    /// Also remove them from the pointer_targets list.
    ///
    /// If this operation would produce an empty value, it replaces it with a `Top` value instead.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.pointer_targets = inner
            .pointer_targets
            .difference(ids_to_remove)
            .cloned()
            .collect();
        for value in inner.memory.values_mut() {
            value.remove_ids(ids_to_remove);
            if value.is_empty() {
                *value = value.top();
            }
        }
        inner.memory.clear_top_values(); // In case the previous operation left *Top* values in the memory struct.
    }

    /// Replace all abstract IDs in `self` with the values given by the replacement map.
    /// IDs not contained as keys in the replacement map are replaced by `Top` values.
    pub fn replace_ids(&mut self, replacement_map: &BTreeMap<AbstractIdentifier, Data>) {
        let inner = Arc::make_mut(&mut self.inner);
        for elem in inner.memory.values_mut() {
            elem.replace_all_ids(replacement_map);
        }
        inner.memory.clear_top_values();
        let mut new_pointer_targets = BTreeSet::new();
        for target in &inner.pointer_targets {
            if let Some(replacement_value) = replacement_map.get(target) {
                for new_target in replacement_value.referenced_ids() {
                    new_pointer_targets.insert(new_target.clone());
                }
            }
        }
        inner.pointer_targets = new_pointer_targets;
    }
}
