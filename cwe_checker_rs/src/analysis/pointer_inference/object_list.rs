use super::object::*;
use super::Data;
use crate::abstract_domain::*;
use crate::bil::Bitvector;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that each abstract identifier can only point to one abstract object.
/// However, an abstract object itself can be marked as non-unique
/// to indicate that it may represent more than one actual memory object.
/// Also, several abstract identifiers may point to the same abstract object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    /// The abstract objects
    objects: Vec<AbstractObject>,
    /// A map from an abstract identifier to the index of the object in the `self.objects` array
    /// and the offset (as `BitvectorDomain`) inside the object that the identifier is pointing to.
    ids: BTreeMap<AbstractIdentifier, (usize, BitvectorDomain)>,
}

impl AbstractObjectList {
    /// Create a new abstract object list with just one abstract object corresponding to the stack.
    /// The offset into the stack object will be set to zero.
    pub fn from_stack_id(
        stack_id: AbstractIdentifier,
        address_bitsize: BitSize,
    ) -> AbstractObjectList {
        let mut objects = Vec::new();
        let stack_object = AbstractObject::new(ObjectType::Stack, address_bitsize);
        objects.push(stack_object);
        let mut ids = BTreeMap::new();
        ids.insert(
            stack_id,
            (0, Bitvector::zero((address_bitsize as usize).into()).into()),
        );
        AbstractObjectList { objects, ids }
    }

    /// Check the state of a memory object at a given address.
    /// Returns True if at least one of the targets of the pointer is dangling.
    /// If `report_none_states` is `true`,
    /// then objects with unknown states get reported if they are unique.
    /// I.e. objects representing more than one actual object (e.g. an array of object) will not get reported,
    /// even if their state is unknown and `report_none_states` is `true`.
    pub fn is_dangling_pointer(&self, address: &Data, report_none_states: bool) -> bool {
        match address {
            Data::Value(_) | Data::Top(_) => (),
            Data::Pointer(pointer) => {
                for id in pointer.ids() {
                    let (object_index, _offset_id) = self.ids.get(id).unwrap();
                    match (report_none_states, self.objects[*object_index].get_state()) {
                        (_, Some(ObjectState::Dangling)) => return true,
                        (true, None) => {
                            if self.objects[*object_index].is_unique {
                                return true;
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
        false
    }

    /// Get the value at a given address.
    /// If the address is not unique, merge the value of all possible addresses.
    ///
    /// Returns an error if the address is a `Data::Value`, i.e. not a pointer.
    pub fn get_value(&self, address: &Data, size: BitSize) -> Result<Data, Error> {
        match address {
            Data::Value(value) => Err(anyhow!("Load from non-pointer value:\n{:?}", value)),
            Data::Top(_) => Ok(Data::new_top(size)),
            Data::Pointer(pointer) => {
                let mut merged_value: Option<Data> = None;
                for (id, offset_pointer_domain) in pointer.targets() {
                    let (abstract_object_index, offset_identifier) = self.ids.get(id).unwrap();
                    let offset = offset_pointer_domain.clone() + offset_identifier.clone();
                    if let BitvectorDomain::Value(concrete_offset) = offset {
                        let value = self
                            .objects
                            .get(*abstract_object_index)
                            .unwrap()
                            .get_value(concrete_offset, size);
                        merged_value = match merged_value {
                            Some(accum) => Some(accum.merge(&value)),
                            None => Some(value),
                        };
                    } else {
                        merged_value = Some(Data::new_top(size));
                        break;
                    }
                }
                merged_value.ok_or_else(|| panic!("Pointer without targets encountered."))
            }
        }
    }

    /// Set the value at a given address.
    ///
    /// If the address has more than one target,
    /// we merge-write the value to all targets.
    pub fn set_value(
        &mut self,
        pointer: PointerDomain<BitvectorDomain>,
        value: Data,
    ) -> Result<(), Error> {
        let mut target_object_set: BTreeSet<usize> = BTreeSet::new();
        for id in pointer.ids() {
            target_object_set.insert(self.ids.get(id).unwrap().0);
        }
        assert!(!target_object_set.is_empty());
        if target_object_set.len() == 1 {
            let mut target_offset: Option<BitvectorDomain> = None;
            for (id, pointer_offset) in pointer.targets() {
                let adjusted_offset = pointer_offset.clone() + self.ids.get(id).unwrap().1.clone();
                target_offset = match target_offset {
                    Some(offset) => Some(offset.merge(&adjusted_offset)),
                    None => Some(adjusted_offset),
                }
            }
            let object = self
                .objects
                .get_mut(*target_object_set.iter().next().unwrap())
                .unwrap();
            object.set_value(value, &target_offset.unwrap())?;
        } else {
            // There is more than one object that the pointer may write to.
            // We merge-write to all possible targets
            for (id, offset) in pointer.targets() {
                let (object_index, object_offset) = self.ids.get(id).unwrap();
                let adjusted_offset = offset.clone() + object_offset.clone();
                self.objects[*object_index].merge_value(value.clone(), &adjusted_offset);
            }
        }
        Ok(())
    }

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
        offset_adjustment: &BitvectorDomain,
    ) {
        let negative_offset = -offset_adjustment.clone();
        for object in self.objects.iter_mut() {
            object.replace_abstract_id(old_id, new_id, &negative_offset);
        }
        if let Some((index, offset)) = self.ids.get(old_id) {
            let (index, offset) = (*index, offset.clone());
            let new_offset = offset + offset_adjustment.clone();
            self.ids.remove(old_id);
            self.ids.insert(new_id.clone(), (index, new_offset));
        }
    }

    /// Remove the pointer from the object_id to the corresponding memory object.
    pub fn remove_object_pointer(&mut self, object_id: &AbstractIdentifier) {
        self.ids.remove(object_id);
    }

    /// Add a new abstract object to the object list
    ///
    /// If an object with the same ID already exists,
    /// the object is marked as non-unique and merged with the newly created object.
    pub fn add_abstract_object(
        &mut self,
        object_id: AbstractIdentifier,
        initial_offset: BitvectorDomain,
        type_: ObjectType,
        address_bitsize: BitSize,
    ) {
        let new_object = AbstractObject::new(type_, address_bitsize);

        if let Some((index, offset)) = self.ids.get(&object_id) {
            // If the identifier already exists, we have to assume that more than one object may be referred by this identifier.
            let object = &mut self.objects[*index];
            object.is_unique = false;
            *object = object.merge(&new_object);
            let index = *index;
            let merged_offset = offset.merge(&initial_offset);
            self.ids.insert(object_id, (index, merged_offset));
        } else {
            let index = self.objects.len();
            self.objects.push(new_object);
            self.ids.insert(object_id, (index, initial_offset));
        }
    }

    /// Return all IDs that get referenced by the memory object pointed to by the given ID.
    pub fn get_referenced_ids(&self, id: &AbstractIdentifier) -> &BTreeSet<AbstractIdentifier> {
        if let Some((index, _offset)) = self.ids.get(id) {
            self.objects[*index].get_referenced_ids()
        } else {
            panic!("Abstract ID not associated to an object")
        }
    }

    /// For abstract IDs not contained in the provided set of IDs
    /// remove the mapping from the ID to the corresponding abstract object.
    /// Then remove all objects not longer referenced by any ID.
    ///
    /// This function does not remove any pointer targets in the contained abstract objects.
    pub fn remove_unused_ids(&mut self, ids_to_keep: &BTreeSet<AbstractIdentifier>) {
        let all_ids: BTreeSet<AbstractIdentifier> = self.ids.keys().cloned().collect();
        let ids_to_remove = all_ids.difference(ids_to_keep);
        for id in ids_to_remove {
            self.ids.remove(id);
        }
        self.remove_unreferenced_objects();
    }

    /// Get all object IDs.
    pub fn get_all_object_ids(&self) -> BTreeSet<AbstractIdentifier> {
        self.ids.keys().cloned().collect()
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    ///
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    /// Returns either a non-empty list of detected errors (like possible double frees) or `OK(())` if no errors were found.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &PointerDomain<BitvectorDomain>,
    ) -> Result<(), Vec<(AbstractIdentifier, Error)>> {
        let ids: Vec<AbstractIdentifier> = object_pointer.ids().cloned().collect();
        let mut possible_double_free_ids = Vec::new();
        if ids.len() > 1 {
            for id in ids {
                if let Err(error) = self.objects[self.ids[&id].0].mark_as_maybe_freed() {
                    possible_double_free_ids.push((id.clone(), error));
                }
            }
        } else if let Some(id) = ids.iter().next() {
            if let Err(error) = self.objects[self.ids[&id].0].mark_as_freed() {
                possible_double_free_ids.push((id.clone(), error));
            }
        } else {
            panic!("Pointer without targets encountered")
        }
        if possible_double_free_ids.is_empty() {
            Ok(())
        } else {
            Err(possible_double_free_ids)
        }
    }

    /// Assume that arbitrary writes happened to a memory object,
    /// including adding pointers to targets contained in `new_possible_reference_targets` to it.
    ///
    /// This is used as a coarse approximation for function calls whose effect is unknown.
    /// Note that this may still underestimate the effect of a function call:
    /// We do not assume that the state of the object changes (i.e. no memory freed), which may not be true.
    /// We assume that pointers to the object are *not* given to other threads or the operating system,
    /// which could result in arbitrary writes to the object even after the function call returned.
    pub fn assume_arbitrary_writes_to_object(
        &mut self,
        object_id: &AbstractIdentifier,
        new_possible_reference_targets: &BTreeSet<AbstractIdentifier>,
    ) {
        let object_index = self.ids[object_id].0;
        self.objects[object_index].assume_arbitrary_writes(new_possible_reference_targets);
    }

    /// Get the number of objects that are currently tracked.
    #[cfg(test)]
    pub fn get_num_objects(&self) -> usize {
        self.objects.len()
    }

    /// Append those objects from another object list, whose abstract IDs are not known to self.
    /// We also add all abstract IDs pointing to the added objects to the ID map.
    pub fn append_unknown_objects(&mut self, other_object_list: &AbstractObjectList) {
        let mut objects_already_known = vec![false; other_object_list.objects.len()];
        for (id, (index, _offset)) in other_object_list.ids.iter() {
            if self.ids.get(id).is_some() {
                objects_already_known[*index] = true;
            }
        }
        let mut old_to_new_index_map: BTreeMap<usize, usize> = BTreeMap::new();
        for (old_index, old_object) in other_object_list.objects.iter().enumerate() {
            if !objects_already_known[old_index] {
                old_to_new_index_map.insert(old_index, self.objects.len());
                self.objects.push(old_object.clone());
            }
        }
        for (id, (old_index, offset)) in other_object_list.ids.iter() {
            if old_to_new_index_map.get(old_index).is_some() {
                self.ids.insert(
                    id.clone(),
                    (old_to_new_index_map[old_index], offset.clone()),
                );
            }
        }
    }

    /// Remove the provided IDs as targets from all pointers in all objects.
    /// Also forget whether the provided IDs point to objects in the object list
    /// and remove objects, that no longer have any ID pointing at them.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        for object in self.objects.iter_mut() {
            object.remove_ids(ids_to_remove);
        }
        self.ids = self
            .ids
            .iter()
            .filter_map(|(id, (index, offset))| {
                if ids_to_remove.get(id).is_none() {
                    Some((id.clone(), (*index, offset.clone())))
                } else {
                    None
                }
            })
            .collect();
        self.remove_unreferenced_objects();
    }

    /// Remove those objects from the object list that have no abstract ID pointing at them.
    fn remove_unreferenced_objects(&mut self) {
        let referenced_objects: BTreeSet<usize> =
            self.ids.values().map(|(index, _offset)| *index).collect();
        if referenced_objects.len() != self.objects.len() {
            // We have to remove some objects and map the object indices to new values
            let mut new_object_list = Vec::new();
            let mut index_map = BTreeMap::new();
            for i in 0..self.objects.len() {
                if referenced_objects.get(&i).is_some() {
                    index_map.insert(i, new_object_list.len());
                    new_object_list.push(self.objects[i].clone());
                }
            }
            self.objects = new_object_list;
            // map the object indices to their new values
            for (index, _offset) in self.ids.values_mut() {
                *index = *index_map.get(index).unwrap();
            }
        }
    }
}

impl AbstractDomain for AbstractObjectList {
    /// Merge two abstract object lists.
    ///
    /// Right now this function is only sound if for each abstract object only one ID pointing to it exists.
    /// Violations of this will be detected and result in panics.
    /// Further investigation into the problem is needed
    /// to decide, how to correctly represent and handle cases,
    /// where more than one ID should point to the same object.
    fn merge(&self, other: &Self) -> Self {
        let mut merged_objects = self.objects.clone();
        let mut merged_ids = self.ids.clone();

        for object_index in 0..other.objects.len() {
            if other
                .ids
                .values()
                .filter(|(index, _offset)| *index == object_index)
                .count()
                > 1
            {
                unimplemented!("Object list with more than one ID pointing to the same object encountered. This is not yet supported.")
            }
        }

        for (other_id, (other_index, other_offset)) in other.ids.iter() {
            if let Some((index, offset)) = merged_ids.get(&other_id) {
                let (index, offset) = (*index, offset.clone());
                merged_ids.insert(other_id.clone(), (index, offset.merge(&other_offset)));
                if index < self.objects.len() {
                    // The object already existed in self, so we have to merge it with the object in other
                    merged_objects[index] =
                        merged_objects[index].merge(&other.objects[*other_index]);
                }
            } else {
                merged_objects.push(other.objects.get(*other_index).unwrap().clone());
                merged_ids.insert(
                    other_id.clone(),
                    (merged_objects.len() - 1, other_offset.clone()),
                );
            }
        }
        AbstractObjectList {
            objects: merged_objects,
            ids: merged_ids,
        }
    }

    /// Always returns `false`, since abstract object lists have no *Top* element.
    fn is_top(&self) -> bool {
        false
    }
}

impl AbstractObjectList {
    /// Get a more compact json-representation of the abstract object list.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut object_list = Vec::new();
        for (index, object) in self.objects.iter().enumerate() {
            let id_list: Vec<Value> = self
                .ids
                .iter()
                .filter_map(|(id, (obj_index, offset))| {
                    if *obj_index == index {
                        Some(Value::String(format!("{}:{}", id, offset)))
                    } else {
                        None
                    }
                })
                .collect();
            let id_list = Value::Array(id_list);
            let mut obj_map = Map::new();
            obj_map.insert("ids".into(), id_list);
            obj_map.insert("object".into(), object.to_json_compact());
            object_list.push(Value::Object(obj_map));
        }
        Value::Array(object_list)
    }
}

#[cfg(test)]
impl AbstractObjectList {
    /// Get access to the internal id map for unit tests
    pub fn get_internal_id_map(&self) -> &BTreeMap<AbstractIdentifier, (usize, BitvectorDomain)> {
        &self.ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(name.into(), 64),
        )
    }

    #[test]
    fn abstract_object_list() {
        let mut obj_list = AbstractObjectList::from_stack_id(new_id("RSP".into()), 64);
        assert_eq!(obj_list.objects.len(), 1);
        assert_eq!(obj_list.ids.len(), 1);
        assert_eq!(*obj_list.ids.values().next().unwrap(), (0, bv(0)));

        let pointer = PointerDomain::new(new_id("RSP".into()), bv(8));
        obj_list
            .set_value(pointer.clone(), Data::Value(bv(42)))
            .unwrap();
        assert_eq!(
            obj_list
                .get_value(&Data::Pointer(pointer.clone()), 64)
                .unwrap(),
            Data::Value(bv(42))
        );

        let mut other_obj_list = AbstractObjectList::from_stack_id(new_id("RSP".into()), 64);
        let second_pointer = PointerDomain::new(new_id("RSP".into()), bv(-8));
        other_obj_list
            .set_value(pointer.clone(), Data::Value(bv(42)))
            .unwrap();
        other_obj_list
            .set_value(second_pointer.clone(), Data::Value(bv(35)))
            .unwrap();
        assert_eq!(
            other_obj_list
                .get_value(&Data::Pointer(second_pointer.clone()), 64)
                .unwrap(),
            Data::Value(bv(35))
        );

        other_obj_list.add_abstract_object(new_id("RAX".into()), bv(0), ObjectType::Heap, 64);
        let heap_pointer = PointerDomain::new(new_id("RAX".into()), bv(8));
        other_obj_list
            .set_value(heap_pointer.clone(), Data::Value(bv(3)))
            .unwrap();

        let mut merged = obj_list.merge(&other_obj_list);
        assert_eq!(
            merged
                .get_value(&Data::Pointer(pointer.clone()), 64)
                .unwrap(),
            Data::Value(bv(42))
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(second_pointer.clone()), 64)
                .unwrap(),
            Data::new_top(64)
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(heap_pointer.clone()), 64)
                .unwrap(),
            Data::Value(bv(3))
        );
        assert_eq!(merged.objects.len(), 2);
        assert_eq!(merged.ids.len(), 2);

        merged
            .set_value(pointer.merge(&heap_pointer), Data::Value(bv(3)))
            .unwrap();
        assert_eq!(
            merged
                .get_value(&Data::Pointer(pointer.clone()), 64)
                .unwrap(),
            Data::Value(BitvectorDomain::new_top(64))
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(heap_pointer.clone()), 64)
                .unwrap(),
            Data::Value(bv(3))
        );
        assert_eq!(merged.objects.len(), 2);

        other_obj_list
            .set_value(pointer.clone(), Data::Pointer(heap_pointer.clone()))
            .unwrap();
        assert_eq!(
            other_obj_list
                .get_referenced_ids(&new_id("RSP".into()))
                .len(),
            1
        );
        assert_eq!(
            *other_obj_list
                .get_referenced_ids(&new_id("RSP".into()))
                .iter()
                .next()
                .unwrap(),
            new_id("RAX".into())
        );

        let modified_heap_pointer = PointerDomain::new(new_id("ID2".into()), bv(8));
        other_obj_list.replace_abstract_id(&new_id("RAX".into()), &new_id("ID2".into()), &bv(0));
        assert_eq!(
            other_obj_list
                .get_value(&Data::Pointer(pointer.clone()), 64)
                .unwrap(),
            Data::Pointer(modified_heap_pointer.clone())
        );
        assert_eq!(other_obj_list.ids.get(&new_id("RAX".into())), None);
        assert!(matches!(
            other_obj_list.ids.get(&new_id("ID2".into())),
            Some(_)
        ));

        let mut ids_to_keep = BTreeSet::new();
        ids_to_keep.insert(new_id("ID2".into()));
        other_obj_list.remove_unused_ids(&ids_to_keep);
        assert_eq!(other_obj_list.objects.len(), 1);
        assert_eq!(other_obj_list.ids.len(), 1);
        assert_eq!(
            other_obj_list.ids.iter().next().unwrap(),
            (&new_id("ID2".into()), &(0, bv(0)))
        );

        assert_eq!(
            other_obj_list.objects[0].get_state(),
            Some(crate::analysis::pointer_inference::object::ObjectState::Alive)
        );
        other_obj_list
            .mark_mem_object_as_freed(&modified_heap_pointer)
            .unwrap();
        assert_eq!(
            other_obj_list.objects[0].get_state(),
            Some(crate::analysis::pointer_inference::object::ObjectState::Dangling)
        );
    }

    #[test]
    fn append_unknown_objects_test() {
        let mut obj_list = AbstractObjectList::from_stack_id(new_id("stack"), 64);

        let mut other_obj_list = AbstractObjectList::from_stack_id(new_id("stack"), 64);
        other_obj_list.add_abstract_object(new_id("heap_obj"), bv(0).into(), ObjectType::Heap, 64);

        obj_list.append_unknown_objects(&other_obj_list);
        assert_eq!(obj_list.objects.len(), 2);
        assert!(obj_list.ids.get(&new_id("stack")).is_some());
        assert!(obj_list.ids.get(&new_id("heap_obj")).is_some());
    }
}
