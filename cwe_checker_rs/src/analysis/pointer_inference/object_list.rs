use super::data::*;
use super::object::*;
use crate::abstract_domain::*;
use crate::bil::Bitvector;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::Arc;

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that each pointer can only point to one abstract object.
/// If a pointer may point to two different abstract objects,
/// these two objects will be merged to one object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    objects: Vec<Arc<AbstractObject>>,
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
        objects.push(Arc::new(stack_object));
        let mut ids = BTreeMap::new();
        ids.insert(
            stack_id,
            (0, Bitvector::zero((address_bitsize as usize).into()).into()),
        );
        AbstractObjectList { objects, ids }
    }

    /// Check the state of a memory object at a given address.
    /// Returns True if at least one of the targets of the pointer is dangling.
    /// May lead to false negatives, as objects with unknown object states are treated the same as alive objects.
    pub fn is_dangling_pointer(&self, address: &Data) -> bool {
        match address {
            Data::Value(_) | Data::Top(_) => (),
            Data::Pointer(pointer) => {
                for (id, _offset) in pointer.iter_targets() {
                    let (object_index, _offset_id) = self.ids.get(id).unwrap();
                    if let AbstractObject::Memory(ref object) = *self.objects[*object_index] {
                        if object.state == Some(ObjectState::Dangling) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Get the value at a given address.
    /// If the address is not unique, merge the value of all possible addresses.
    ///
    /// TODO: document when this function should return errors
    pub fn get_value(&self, address: &Data, size: BitSize) -> Result<Data, Error> {
        match address {
            Data::Value(value) => Err(anyhow!("Load from non-pointer value:\n{:?}", value)),
            Data::Top(_) => Ok(Data::new_top(size)),
            Data::Pointer(pointer) => {
                // TODO: Document the design decisions behind the implementation!
                let mut merged_value: Option<Data> = None;
                for (id, offset_pointer_domain) in pointer.iter_targets() {
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
                merged_value.ok_or_else(|| anyhow!("Pointer without targets encountered."))
            }
        }
    }

    /// Set the value at a given address.
    ///
    /// Returns an error if the gitven address has no targets.
    /// If the address has more than one target, all targets are merged to one untracked object.
    // TODO: Implement write-merging to  still tracked objects!
    pub fn set_value(&mut self, pointer: PointerDomain, value: Data) -> Result<(), Error> {
        let mut target_object_set: BTreeSet<usize> = BTreeSet::new();
        for (id, _offset) in pointer.iter_targets() {
            target_object_set.insert(self.ids.get(id).unwrap().0);
        }
        if target_object_set.is_empty() {
            return Err(anyhow!("Pointer without targets encountered"));
        }
        if target_object_set.len() == 1 {
            let mut target_offset: Option<BitvectorDomain> = None;
            for (id, pointer_offset) in pointer.iter_targets() {
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
            Arc::make_mut(object).set_value(value, target_offset.unwrap())?; // TODO: Write unit test whether this is correctly written to the self.objects vector!
        } else {
            // There is more than one object that the pointer may write to.
            // We merge all targets to one untracked object
            // TODO: Implement merging to a still tracked object!

            // Get all pointer targets the object may point to
            let mut inner_targets: BTreeSet<AbstractIdentifier> = BTreeSet::new();
            for object in target_object_set.iter() {
                inner_targets.append(
                    &mut self
                        .objects
                        .get(*object)
                        .unwrap()
                        .get_all_possible_pointer_targets(),
                );
            }
            // Generate the new (untracked) object that all other objects are merged to
            let new_object = AbstractObject::Untracked(inner_targets);
            // generate the ne map from abstract identifier to index of corresponding memory object
            let mut index_map = BTreeMap::new();
            let mut new_object_vec: Vec<Arc<AbstractObject>> = Vec::new();
            for old_index in 0..self.objects.len() {
                if target_object_set.get(&old_index).is_none() {
                    index_map.insert(old_index, new_object_vec.len());
                    new_object_vec.push(self.objects.get(old_index).unwrap().clone());
                }
            }
            new_object_vec.push(Arc::new(new_object));
            let merged_object_index = new_object_vec.len() - 1;
            for old_index in target_object_set {
                index_map.insert(old_index, merged_object_index);
            }
            let mut new_id_map: BTreeMap<AbstractIdentifier, (usize, BitvectorDomain)> =
                BTreeMap::new();
            for (id, (old_index, offset)) in self.ids.iter() {
                new_id_map.insert(id.clone(), (index_map[old_index], offset.clone()));
            }
            self.objects = new_object_vec;
            self.ids = new_id_map;
            // now we can do the actual write operation on the newly merged object
            // the offset does not matter since the merged object is untracked anyway
            Arc::make_mut(self.objects.get_mut(merged_object_index).unwrap())
                .set_value(value, BitvectorDomain::new_top(pointer.bitsize()))?;
        }
        Ok(())
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_objects = self.objects.clone();
        let mut merged_ids = self.ids.clone();
        for (other_id, (other_index, other_offset)) in other.ids.iter() {
            if let Some((index, offset)) = merged_ids.get(&other_id) {
                let (index, offset) = (*index, offset.clone());
                merged_ids.insert(other_id.clone(), (index, offset.merge(&other_offset)));
                if index < self.objects.len() {
                    // The object already existed in self, so we have to merge it with the object in other
                    merged_objects[index] =
                        Arc::new(merged_objects[index].merge(&other.objects[*other_index]));
                    // TODO: This is still inefficient, since we may end up merging the same objects more than once (if several ids point to it)
                }
            } else {
                merged_objects.push(other.objects.get(*other_index).unwrap().clone());
                merged_ids.insert(
                    other_id.clone(),
                    (merged_objects.len() - 1, other_offset.clone()),
                );
            }
        }
        // merge the underlying abstract objects.
        AbstractObjectList {
            objects: merged_objects,
            ids: merged_ids,
        }
    }

    /// Replace one abstract identifier with another one. Adjust offsets of all pointers accordingly.
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
        offset_adjustment: &BitvectorDomain,
    ) {
        for object in self.objects.iter_mut() {
            Arc::make_mut(object).replace_abstract_id(
                old_id,
                new_id,
                &(-offset_adjustment.clone()),
            );
        }
        if let Some((index, offset)) = self.ids.get(old_id) {
            let index = *index;
            // Note that we have to *subtract* the offset offset_adjustment to get the new offset,
            // since the offset_adjustment gets added to all pointers.
            // This way all pointers will still point to the same place in memory.
            let new_offset = offset.clone() + offset_adjustment.clone();
            self.ids.remove(old_id);
            self.ids.insert(new_id.clone(), (index, new_offset));
        }
    }

    /// Remove the pointer from the object_id to the corresponding memory object.
    pub fn remove_object_pointer(&mut self, object_id: &AbstractIdentifier) {
        self.ids.remove(object_id);
    }

    /// Add a new abstract object to the object list
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
            let object = Arc::make_mut(&mut self.objects[*index]);
            if let AbstractObject::Memory(object_info) = object {
                object_info.is_unique = false;
            }
            *object = object.merge(&new_object);
            let index = *index;
            let merged_offset = offset.merge(&initial_offset);
            self.ids.insert(object_id, (index, merged_offset));
        } else {
            let index = self.objects.len();
            self.objects.push(Arc::new(new_object));
            self.ids.insert(object_id, (index, initial_offset));
        }
    }

    /// return all ids that get referenced by the memory object pointed to by the given id
    pub fn get_referenced_ids(&self, id: &AbstractIdentifier) -> BTreeSet<AbstractIdentifier> {
        if let Some((index, _offset)) = self.ids.get(id) {
            self.objects[*index].get_referenced_ids()
        } else {
            BTreeSet::new()
        }
    }

    /// Remove all abstract identifier not contained in the provided set of identifier.
    /// Then remove all objects not longer referenced by any identifier.
    pub fn remove_unused_ids(&mut self, ids_to_keep: &BTreeSet<AbstractIdentifier>) {
        let all_ids: BTreeSet<AbstractIdentifier> = self.ids.keys().cloned().collect();
        let ids_to_remove = all_ids.difference(ids_to_keep);
        for id in ids_to_remove {
            self.ids.remove(id);
        }
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

    /// Get all object ids
    pub fn get_all_object_ids(&self) -> BTreeSet<AbstractIdentifier> {
        self.ids.keys().cloned().collect()
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &PointerDomain,
    ) -> Result<(), Vec<AbstractIdentifier>> {
        let ids = object_pointer.get_target_ids();
        let mut possible_double_free_ids = Vec::new();
        if ids.len() > 1 {
            for id in ids {
                let object = &mut self.objects[self.ids[&id].0];
                if let AbstractObject::Memory(tracked_mem) = Arc::deref(object) {
                    if (tracked_mem.state != Some(ObjectState::Alive) && tracked_mem.is_unique)
                        || tracked_mem.state == Some(ObjectState::Dangling)
                    {
                        // Possible double free detected
                        // TODO: Check rate of false positives.
                        // If too high, only mark those with explicit dangling state.
                        possible_double_free_ids.push(id.clone());
                    }
                }
                Arc::make_mut(object).set_state(None);
            }
        } else if let Some(id) = ids.iter().next() {
            let object = &mut self.objects[self.ids[&id].0];
            if let AbstractObject::Memory(tracked_mem) = Arc::deref(object) {
                if tracked_mem.state != Some(ObjectState::Alive) {
                    // Possible double free detected
                    // TODO: Check rate of false positives.
                    // If too high, only mark those with explicit dangling state.
                    possible_double_free_ids.push(id.clone());
                }
            }
            Arc::make_mut(object).set_state(Some(ObjectState::Dangling));
        }
        if possible_double_free_ids.is_empty() {
            Ok(())
        } else {
            Err(possible_double_free_ids)
        }
    }

    /// Mark the memory object behind an abstract identifier as untracked.
    /// Also add new possible reference targets to the object.
    ///
    /// This is used as a very coarse approximation for function calls whose effect is unknown.
    /// Since a function may spawn a new thread constantly writing to this memory object,
    /// the content of the memory object may not become known later on.
    /// The new reference targets are added because we also do not know whether the function adds pointers to the memory object.
    pub fn mark_mem_object_as_untracked(
        &mut self,
        object_id: &AbstractIdentifier,
        new_possible_reference_targets: &BTreeSet<AbstractIdentifier>,
    ) {
        let object_index = self.ids[object_id].0;
        let reference_targets = self.objects[object_index]
            .get_all_possible_pointer_targets()
            .union(new_possible_reference_targets)
            .cloned()
            .collect();
        self.objects[object_index] = Arc::new(AbstractObject::Untracked(reference_targets));
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
    /// Also forget whether the provided IDs point to objects in the object list.
    ///
    /// This may leave objects without known IDs pointing to them.
    /// This function does *not* trim these objects from the object list.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        for object in self.objects.iter_mut() {
            let object = Arc::make_mut(object);
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
    }
}

impl AbstractObjectList {
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

    fn new_id(name: String) -> AbstractIdentifier {
        AbstractIdentifier::new(Tid::new("time0"), AbstractLocation::Register(name, 64))
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
            Data::new_top(64)
        );
        // assert_eq!(merged.get_value(&Data::Pointer(heap_pointer.clone()), 64).unwrap(), Data::Value(bv(3)));
        assert_eq!(merged.objects.len(), 1); // This will fail in the future when the set_value function does no automatic merging to untracked objects anymore.

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
}
