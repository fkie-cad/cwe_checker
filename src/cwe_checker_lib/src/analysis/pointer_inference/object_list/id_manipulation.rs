//! Methods of [`AbstractObjectList`] related to manipulating abstract IDs.

use super::*;

impl AbstractObjectList {
    /// Replace one abstract identifier with another one. Adjust offsets of all pointers accordingly.
    ///
    /// **Example:**
    /// Assume the `old_id` points to offset 0 in the corresponding memory object and the `new_id` points to offset -32.
    /// Then the offset_adjustment is -32.
    /// The offset_adjustment gets *added* to the base offset in `self.memory.ids` (so that it points to offset -32 in the memory object),
    /// while it gets *subtracted* from all pointer values (so that they still point to the same spot in the corresponding memory object).
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &ValueDomain,
    ) {
        let negative_offset = -offset_adjustment.clone();
        for (object, _) in self.objects.values_mut() {
            object.replace_abstract_id(old_id, new_id, &negative_offset);
        }
        if let Some((object, old_offset)) = self.objects.remove(old_id) {
            let new_offset = old_offset + offset_adjustment.clone();
            self.objects.insert(new_id.clone(), (object, new_offset));
        }
    }

    /// Return all IDs that may be referenced by the memory object pointed to by the given ID.
    /// The returned set is an overapproximation of the actual referenced IDs.
    pub fn get_referenced_ids_overapproximation(
        &self,
        id: &AbstractIdentifier,
    ) -> BTreeSet<AbstractIdentifier> {
        if let Some((object, _offset)) = self.objects.get(id) {
            object.get_referenced_ids_overapproximation().clone()
        } else {
            BTreeSet::new()
        }
    }

    /// Return all IDs that get referenced by the memory object pointed to by the given ID.
    /// The returned set is an underapproximation of the actual referenced IDs,
    /// since only still tracked pointers inside the memory object are used to compute it.
    pub fn get_referenced_ids_underapproximation(
        &self,
        id: &AbstractIdentifier,
    ) -> BTreeSet<AbstractIdentifier> {
        if let Some((object, _offset)) = self.objects.get(id) {
            object.get_referenced_ids_underapproximation()
        } else {
            panic!("Abstract ID not associated to an object")
        }
    }
}