//! Methods of [`AbstractObjectList`] that add or remove objects from the object list
//! or provide information about the set of objects in the object list.

use super::*;

impl AbstractObjectList {
    /// Get a reference to the object corresponding to the given ID.
    pub fn get_object(&self, id: &AbstractIdentifier) -> Option<&AbstractObject> {
        self.objects.get(id)
    }

    /// Add a new abstract object to the object list
    ///
    /// If an object with the same ID already exists,
    /// the object is marked as non-unique and merged with the newly created object.
    pub fn add_abstract_object(
        &mut self,
        object_id: AbstractIdentifier,
        generic_address_bytesize: ByteSize,
        type_: Option<ObjectType>,
    ) {
        let new_object = AbstractObject::new(type_, generic_address_bytesize);
        if let Some(object) = self.objects.get_mut(&object_id) {
            // If the identifier already exists, we have to assume that more than one object may be referenced by this identifier.
            object.mark_as_not_unique();
            *object = object.merge(&new_object);
        } else {
            self.objects.insert(object_id, new_object);
        }
    }

    /// Insert an existing object to the object list.
    /// If the object identifier already exists, the object is marked as non-unique
    /// and merged with the corresponding object already present in the object list.
    pub fn insert(&mut self, id: AbstractIdentifier, object: AbstractObject) {
        if let Some(existing_object) = self.objects.get_mut(&id) {
            existing_object.mark_as_not_unique();
            *existing_object = existing_object.merge(&object);
        } else {
            self.objects.insert(id, object);
        }
    }

    /// For abstract IDs not contained in the provided set of IDs
    /// remove the corresponding abstract objects.
    ///
    /// This function does not remove any pointer targets in the contained abstract objects.
    pub fn remove_unused_objects(&mut self, ids_to_keep: &BTreeSet<AbstractIdentifier>) {
        let all_ids: BTreeSet<AbstractIdentifier> = self.objects.keys().cloned().collect();
        let ids_to_remove = all_ids.difference(ids_to_keep);
        for id in ids_to_remove {
            self.objects.remove(id);
        }
    }

    /// Get all object IDs.
    pub fn get_all_object_ids(&self) -> BTreeSet<AbstractIdentifier> {
        self.objects.keys().cloned().collect()
    }

    /// Get an iterator over the contained abstract objects in `self`.
    pub fn iter(&self) -> std::collections::btree_map::Iter<AbstractIdentifier, AbstractObject> {
        self.objects.iter()
    }

    /// Get the number of objects that are currently tracked.
    #[cfg(test)]
    pub fn get_num_objects(&self) -> usize {
        self.objects.len()
    }
}
