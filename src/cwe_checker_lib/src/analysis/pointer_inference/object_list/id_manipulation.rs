//! Methods of [`AbstractObjectList`] related to manipulating abstract IDs.

use super::*;

impl AbstractObjectList {
    /// Return all IDs that may be referenced by the memory object pointed to by the given ID.
    /// The returned set is an overapproximation of the actual referenced IDs.
    pub fn get_referenced_ids_overapproximation(
        &self,
        id: &AbstractIdentifier,
    ) -> BTreeSet<AbstractIdentifier> {
        if let Some(object) = self.objects.get(id) {
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
        if let Some(object) = self.objects.get(id) {
            object.get_referenced_ids_underapproximation()
        } else {
            BTreeSet::new()
        }
    }
}
