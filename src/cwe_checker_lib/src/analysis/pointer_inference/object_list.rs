use super::object::*;
use super::{Data, ValueDomain};
use crate::prelude::*;
use crate::{abstract_domain::*, utils::binary::RuntimeMemoryImage};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that there is exactly one abstract identifier pointing to it.
/// However, an abstract object itself can be marked as non-unique
/// to indicate that it may represent more than one actual memory object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    /// The abstract objects.
    ///
    /// Each abstract object comes with an offset given as a [`ValueDomain`].
    /// This offset determines where the zero offset corresponding to the abstract identifier inside the object is.
    /// Note that this offset may be a `Top` element
    /// if the exact offset corresponding to the identifier is unknown.
    objects: BTreeMap<AbstractIdentifier, (AbstractObject, ValueDomain)>,
}

impl AbstractObjectList {
    /// Create a new abstract object list with just one abstract object corresponding to the stack.
    ///
    /// The offset into the stack object and the `upper_index_bound` of the stack object will be both set to zero.
    /// This corresponds to the generic stack state at the start of a function.
    pub fn from_stack_id(
        stack_id: AbstractIdentifier,
        address_bytesize: ByteSize,
    ) -> AbstractObjectList {
        let mut objects = BTreeMap::new();
        let mut stack_object = AbstractObject::new(ObjectType::Stack, address_bytesize);
        stack_object.set_upper_index_bound(Bitvector::zero(address_bytesize.into()).into());
        objects.insert(
            stack_id,
            (
                stack_object,
                Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
            ),
        );
        AbstractObjectList { objects }
    }

    /// Check the state of a memory object at a given address.
    /// Returns `true` if at least one of the targets of the pointer is dangling.
    /// If `report_unknown_states` is `true`,
    /// then objects with unknown states get reported if they are unique.
    /// I.e. objects representing more than one actual object (e.g. an array of object) will not get reported,
    /// even if their state is unknown and `report_unknown_states` is `true`.
    pub fn is_dangling_pointer(&self, address: &Data, report_unknown_states: bool) -> bool {
        match address {
            Data::Value(_) | Data::Top(_) => (),
            Data::Pointer(pointer) => {
                for id in pointer.ids() {
                    let (object, _offset_id) = self.objects.get(id).unwrap();
                    match (report_unknown_states, object.get_state()) {
                        (_, ObjectState::Dangling) => return true,
                        (true, ObjectState::Unknown) => {
                            if object.is_unique {
                                return true;
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
        // No dangling pointer found
        false
    }

    /// Check whether a memory access at the given address (and accessing `size` many bytes)
    /// may be an out-of-bounds memory access.
    ///
    /// Note that `Top` values as addresses are not marked as out-of-bounds,
    /// since they are more likely due to analysis imprecision than to actual out-of-bounds access.
    pub fn is_out_of_bounds_mem_access(
        &self,
        address: &Data,
        size: ByteSize,
        global_data: &RuntimeMemoryImage,
    ) -> bool {
        match address {
            Data::Value(value) => {
                if let Ok((start, end)) = value.try_to_offset_interval() {
                    if start < 0 || end < start {
                        return true;
                    }
                    return global_data
                        .is_interval_readable(start as u64, end as u64 + u64::from(size) - 1)
                        .is_err();
                }
            }
            Data::Top(_) => (),
            Data::Pointer(pointer) => {
                for (id, offset) in pointer.targets() {
                    let (object, base_offset) = self.objects.get(id).unwrap();
                    let adjusted_offset = offset.clone() + base_offset.clone();
                    if !adjusted_offset.is_top()
                        && !object.access_contained_in_bounds(&adjusted_offset, size)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Set the lower index bound for indices to be considered inside the memory object.
    /// The bound is inclusive, i.e. the bound index itself is also considered to be inside the memory object.
    ///
    /// Any `bound` value other than a constant bitvector is interpreted as the memory object not having a lower bound.
    pub fn set_lower_index_bound(&mut self, object_id: &AbstractIdentifier, bound: &ValueDomain) {
        let (object, base_offset) = self.objects.get_mut(object_id).unwrap();
        let bound = (bound.clone() + base_offset.clone())
            .try_to_bitvec()
            .map(|bitvec| bitvec.into())
            .unwrap_or_else(|_| BitvectorDomain::new_top(bound.bytesize()));
        object.set_lower_index_bound(bound);
    }

    /// Set the upper index bound for indices to be considered inside the memory object.
    /// The bound is inclusive, i.e. the bound index itself is also considered to be inside the memory object.
    ///
    /// Any `bound` value other than a constant bitvector is interpreted as the memory object not having an upper bound.
    pub fn set_upper_index_bound(&mut self, object_id: &AbstractIdentifier, bound: &ValueDomain) {
        let (object, base_offset) = self.objects.get_mut(object_id).unwrap();
        let bound = (bound.clone() + base_offset.clone())
            .try_to_bitvec()
            .map(|bitvec| bitvec.into())
            .unwrap_or_else(|_| BitvectorDomain::new_top(bound.bytesize()));
        object.set_upper_index_bound(bound);
    }

    /// Get the value at a given address.
    /// If the address is not unique, merge the value of all possible addresses.
    ///
    /// Returns an error if the address is a `Data::Value`, i.e. not a pointer.
    pub fn get_value(&self, address: &Data, size: ByteSize) -> Result<Data, Error> {
        match address {
            Data::Value(_) => Err(anyhow!("Load from non-pointer value")),
            Data::Top(_) => Ok(Data::new_top(size)),
            Data::Pointer(pointer) => {
                let mut merged_value: Option<Data> = None;
                for (id, offset_pointer_domain) in pointer.targets() {
                    let (object, offset_identifier) = self.objects.get(id).unwrap();
                    let offset = offset_pointer_domain.clone() + offset_identifier.clone();
                    if let Ok(concrete_offset) = offset.try_to_bitvec() {
                        let value = object.get_value(concrete_offset, size);
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
        pointer: PointerDomain<ValueDomain>,
        value: Data,
    ) -> Result<(), Error> {
        let targets = pointer.targets();
        assert!(!targets.is_empty());
        if targets.len() == 1 {
            let (id, pointer_offset) = targets.iter().next().unwrap();
            let (object, id_offset) = self.objects.get_mut(id).unwrap();
            let adjusted_offset = pointer_offset.clone() + id_offset.clone();
            object.set_value(value, &adjusted_offset)
        } else {
            // There is more than one object that the pointer may write to.
            // We merge-write to all possible targets
            for (id, offset) in targets {
                let (object, object_offset) = self.objects.get_mut(id).unwrap();
                let adjusted_offset = offset.clone() + object_offset.clone();
                object.merge_value(value.clone(), &adjusted_offset);
            }
            Ok(())
        }
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
            object.is_unique = false;
            *object = object.merge(&new_object);
            *offset = offset.merge(&initial_offset);
        } else {
            self.objects.insert(object_id, (new_object, initial_offset));
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

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    ///
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    /// Returns either a non-empty list of detected errors (like possible double frees) or `OK(())` if no errors were found.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &PointerDomain<ValueDomain>,
    ) -> Result<(), Vec<(AbstractIdentifier, Error)>> {
        let ids: Vec<AbstractIdentifier> = object_pointer.ids().cloned().collect();
        let mut possible_double_free_ids = Vec::new();
        if ids.len() > 1 {
            for id in ids {
                if let Err(error) = self.objects.get_mut(&id).unwrap().0.mark_as_maybe_freed() {
                    possible_double_free_ids.push((id.clone(), error));
                }
            }
        } else if let Some(id) = ids.get(0) {
            if let Err(error) = self.objects.get_mut(&id).unwrap().0.mark_as_freed() {
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
        if let Some((object, _)) = self.objects.get_mut(object_id) {
            object.assume_arbitrary_writes(new_possible_reference_targets);
        }
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

    /// Return the object type of a memory object.
    /// Returns an error if no object with the given ID is contained in the object list.
    pub fn get_object_type(
        &self,
        object_id: &AbstractIdentifier,
    ) -> Result<Option<ObjectType>, ()> {
        match self.objects.get(object_id) {
            Some((object, _)) => Ok(object.get_object_type()),
            None => Err(()),
        }
    }

    /// Returns `true` if the object corresponding to the given ID represents an unique object
    /// and `false` if it may represent more than one object (e.g. several array elements).
    /// Returns an error if the ID is not contained in the object list.
    pub fn is_unique_object(&self, object_id: &AbstractIdentifier) -> Result<bool, Error> {
        match self.objects.get(object_id) {
            Some((object, _)) => Ok(object.is_unique),
            None => Err(anyhow!("Object ID not contained in object list.")),
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
        for (id, (other_object, other_offset)) in other.objects.iter() {
            if let Some((object, offset)) = merged_objects.get_mut(id) {
                *object = object.merge(other_object);
                *offset = offset.merge(other_offset);
            } else {
                merged_objects.insert(id.clone(), (other_object.clone(), other_offset.clone()));
            }
        }
        AbstractObjectList {
            objects: merged_objects,
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
        let mut object_map = Map::new();
        for (id, (object, offset)) in self.objects.iter() {
            object_map.insert(
                format!("{} (base offset {})", id, offset),
                object.to_json_compact(),
            );
        }
        Value::Object(object_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(value: i64) -> ValueDomain {
        ValueDomain::from(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(name.into(), ByteSize::new(8)),
        )
    }

    #[test]
    fn abstract_object_list() {
        let mut obj_list =
            AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
        assert_eq!(obj_list.objects.len(), 1);
        assert_eq!(obj_list.objects.values().next().unwrap().1, bv(0));

        let pointer = PointerDomain::new(new_id("RSP".into()), bv(8));
        obj_list
            .set_value(pointer.clone(), Data::Value(bv(42)))
            .unwrap();
        assert_eq!(
            obj_list
                .get_value(&Data::Pointer(pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(bv(42))
        );

        let mut other_obj_list =
            AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
        let second_pointer = PointerDomain::new(new_id("RSP".into()), bv(-8));
        other_obj_list
            .set_value(pointer.clone(), Data::Value(bv(42)))
            .unwrap();
        other_obj_list
            .set_value(second_pointer.clone(), Data::Value(bv(35)))
            .unwrap();
        assert_eq!(
            other_obj_list
                .get_value(&Data::Pointer(second_pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(bv(35))
        );

        other_obj_list.add_abstract_object(
            new_id("RAX".into()),
            bv(0),
            ObjectType::Heap,
            ByteSize::new(8),
        );
        let heap_pointer = PointerDomain::new(new_id("RAX".into()), bv(8));
        other_obj_list
            .set_value(heap_pointer.clone(), Data::Value(bv(3)))
            .unwrap();

        let mut merged = obj_list.merge(&other_obj_list);
        assert_eq!(
            merged
                .get_value(&Data::Pointer(pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(bv(42))
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(second_pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::new_top(ByteSize::new(8))
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(heap_pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(bv(3))
        );
        assert_eq!(merged.objects.len(), 2);

        merged
            .set_value(pointer.merge(&heap_pointer), Data::Value(bv(3)))
            .unwrap();
        assert_eq!(
            merged
                .get_value(&Data::Pointer(pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(ValueDomain::new_top(ByteSize::new(8)))
        );
        assert_eq!(
            merged
                .get_value(&Data::Pointer(heap_pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Value(bv(3))
        );
        assert_eq!(merged.objects.len(), 2);

        other_obj_list
            .set_value(pointer.clone(), Data::Pointer(heap_pointer.clone()))
            .unwrap();
        assert_eq!(
            other_obj_list
                .get_referenced_ids_overapproximation(&new_id("RSP".into()))
                .len(),
            1
        );
        assert_eq!(
            *other_obj_list
                .get_referenced_ids_overapproximation(&new_id("RSP".into()))
                .iter()
                .next()
                .unwrap(),
            new_id("RAX".into())
        );

        let modified_heap_pointer = PointerDomain::new(new_id("ID2".into()), bv(8));
        other_obj_list.replace_abstract_id(&new_id("RAX".into()), &new_id("ID2".into()), &bv(0));
        assert_eq!(
            other_obj_list
                .get_value(&Data::Pointer(pointer.clone()), ByteSize::new(8))
                .unwrap(),
            Data::Pointer(modified_heap_pointer.clone())
        );
        assert_eq!(other_obj_list.objects.get(&new_id("RAX".into())), None);
        assert!(matches!(
            other_obj_list.objects.get(&new_id("ID2".into())),
            Some(_)
        ));

        let mut ids_to_keep = BTreeSet::new();
        ids_to_keep.insert(new_id("ID2".into()));
        other_obj_list.remove_unused_objects(&ids_to_keep);
        assert_eq!(other_obj_list.objects.len(), 1);
        assert_eq!(
            other_obj_list.objects.iter().next().unwrap().0,
            &new_id("ID2".into())
        );

        assert_eq!(
            other_obj_list
                .objects
                .values()
                .next()
                .unwrap()
                .0
                .get_state(),
            crate::analysis::pointer_inference::object::ObjectState::Alive
        );
        other_obj_list
            .mark_mem_object_as_freed(&modified_heap_pointer)
            .unwrap();
        assert_eq!(
            other_obj_list
                .objects
                .values()
                .next()
                .unwrap()
                .0
                .get_state(),
            crate::analysis::pointer_inference::object::ObjectState::Dangling
        );
    }

    #[test]
    fn append_unknown_objects_test() {
        let mut obj_list = AbstractObjectList::from_stack_id(new_id("stack"), ByteSize::new(8));

        let mut other_obj_list =
            AbstractObjectList::from_stack_id(new_id("stack"), ByteSize::new(8));
        other_obj_list.add_abstract_object(
            new_id("heap_obj"),
            bv(0).into(),
            ObjectType::Heap,
            ByteSize::new(8),
        );

        obj_list.append_unknown_objects(&other_obj_list);
        assert_eq!(obj_list.objects.len(), 2);
        assert!(obj_list.objects.get(&new_id("stack")).is_some());
        assert!(obj_list.objects.get(&new_id("heap_obj")).is_some());
    }
}
