//! Methods of [`AbstractObjectList`] that add or remove objects from the object list
//! or provide information about the set of objects in the object list.

use super::*;

impl AbstractObjectList {
    /// Remove the memory object that `object_id` points to from the object list.
    pub fn remove_object(&mut self, object_id: &AbstractIdentifier) {
        self.objects.remove(object_id);
    }

    /// Add a new abstract object to the object list
    ///
    /// If an object with the same ID already exists,
    /// the object is marked as non-unique and merged with the newly created object.
    pub fn add_abstract_object(
        &mut self,
        object_id: AbstractIdentifier,
        initial_offset: ValueDomain,
        type_: ObjectType,
        address_bytesize: ByteSize,
    ) {
        let new_object = AbstractObject::new(type_, address_bytesize);
        if let Some((object, offset)) = self.objects.get_mut(&object_id) {
            // If the identifier already exists, we have to assume that more than one object may be referenced by this identifier.
            object.mark_as_not_unique();
            *object = object.merge(&new_object);
            *offset = offset.merge(&initial_offset);
        } else {
            self.objects.insert(object_id, (new_object, initial_offset));
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

    /// Get the number of objects that are currently tracked.
    #[cfg(test)]
    pub fn get_num_objects(&self) -> usize {
        self.objects.len()
    }

    /// Append those objects from another object list, whose abstract IDs are not known to self.
    pub fn append_unknown_objects(&mut self, other_object_list: &AbstractObjectList) {
        for (id, (other_object, other_offset)) in other_object_list.objects.iter() {
            if self.objects.get(id) == None {
                self.objects
                    .insert(id.clone(), (other_object.clone(), other_offset.clone()));
            }
        }
    }

    /// Remove the provided IDs as targets from all pointers in all objects.
    /// Also remove the objects, that these IDs point to.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        for id in ids_to_remove {
            if self.objects.get(id).is_some() {
                self.objects.remove(id);
            }
        }
        for (object, _) in self.objects.values_mut() {
            object.remove_ids(ids_to_remove);
        }
    }
}