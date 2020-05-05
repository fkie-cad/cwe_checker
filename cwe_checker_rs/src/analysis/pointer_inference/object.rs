use super::data::*;
use super::identifier::AbstractIdentifier;
use crate::analysis::abstract_domain::*;
use crate::analysis::mem_region::MemRegion;
use crate::bil::Bitvector;
use crate::prelude::*;
use apint::Width;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    pub fn from_stack_id(stack_id: AbstractIdentifier, address_bitsize: BitSize) -> AbstractObjectList {
        let mut objects = Vec::new();
        let stack_object = AbstractObject::new(ObjectType::Stack, address_bitsize);
        objects.push(Arc::new(stack_object));
        let mut ids = BTreeMap::new();
        ids.insert(stack_id, (0, Bitvector::zero((address_bitsize as usize).into()).into()));
        AbstractObjectList {
            objects,
            ids,
        }
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
                        let value =
                            self.objects[*abstract_object_index].get_value(concrete_offset, size);
                        merged_value = match merged_value {
                            Some(accum) => Some(accum.merge(&value)),
                            None => Some(value),
                        };
                    } else {
                        merged_value = Some(Data::new_top(size));
                        break;
                    }
                }
                merged_value.ok_or(anyhow!("Pointer without targets encountered."))
            }
        }
    }

    pub fn set_value(&mut self, pointer: PointerDomain, value: Data) -> Result<(), Error> {
        let mut target_object_set: BTreeSet<usize> = BTreeSet::new();
        for (id, offset) in pointer.iter_targets() {
            target_object_set.insert(self.ids[id].0);
        }
        assert!(target_object_set.len() != 0);
        if target_object_set.len() == 1 {
            let mut target_offset: Option<BitvectorDomain> = None;
            for (id, pointer_offset) in pointer.iter_targets() {
                let adjusted_offset = pointer_offset.clone() + self.ids[id].1.clone();
                target_offset = match target_offset {
                    Some(offset) => Some(offset.merge(&adjusted_offset)),
                    None => Some(adjusted_offset),
                }
            }
            let object = &mut self.objects[*target_object_set.iter().next().unwrap()];
            Arc::make_mut(object).set_value(value, target_offset.unwrap())?; // TODO: Write unit test whether this is correctly written to the self.objects vector!
        } else {
            // There is more than one object that the pointer may write to.
            // We merge all targets to one untracked object
            // TODO: Implement merging to a still tracked object!

            // Get all pointer targets the object may point to
            let mut inner_targets: BTreeSet<AbstractIdentifier> = BTreeSet::new();
            for object in target_object_set.iter() {
                inner_targets.append(&mut self.objects[*object].get_all_possible_pointer_targets());
            }
            // Generate the new (untracked) object that all other objects are merged to
            let new_object = AbstractObject::Untracked(inner_targets);
            // generate the ne map from abstract identifier to index of corresponding memory object
            let mut index_map = BTreeMap::new();
            let mut new_object_vec: Vec<Arc<AbstractObject>> = Vec::new();
            for old_index in 0..self.objects.len() {
                if target_object_set.get(&old_index).is_none() {
                    index_map.insert(old_index, new_object_vec.len());
                    new_object_vec.push(self.objects[old_index].clone());
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
            Arc::make_mut(&mut self.objects[merged_object_index])
                .set_value(value, BitvectorDomain::new_top(pointer.bitsize()))?;
        }
        Ok(())
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_objects = self.objects.clone();
        let mut merged_ids = self.ids.clone();
        for (other_id, (other_index, other_offset)) in other.ids.iter() {
            if let Some((index, offset)) = merged_ids.get(&other_id).clone() {
                let (index, offset) = (*index, offset.clone());
                merged_ids.insert(other_id.clone(), (index, offset.merge(&other_offset)));
            } else {
                merged_objects.push(other.objects[*other_index].clone());
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

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        for object in self.objects.iter_mut() {
            Arc::make_mut(object).replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        if let Some((index, offset)) = self.ids.get(old_id) {
            let index = *index;
            // Note that we have to *subtract* the offset offset_adjustment to get the new offset,
            // since the offset_adjustment gets added to all pointers.
            // This way all pointers will still point to the same place in memory.
            let new_offset = offset.clone() - offset_adjustment.clone();
            self.ids.remove(old_id);
            self.ids.insert(new_id.clone(), (index, new_offset));
        }
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

    // Remove all abstract identifier not contained in the provided set of identifier.
    // Then remove all objects not longer referenced by any identifier.
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

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    pub fn mark_mem_object_as_freed(&mut self, object_pointer: &PointerDomain) {
        let ids = object_pointer.get_target_ids();
        if ids.len() > 1 {
            for id in ids {
                let object = &mut self.objects[self.ids[&id].0];
                Arc::make_mut(object).set_state(None);
            }
        } else {
            if let Some(id) = ids.iter().next() {
                let object = &mut self.objects[self.ids[&id].0];
                Arc::make_mut(object).set_state(Some(ObjectState::Dangling));
            }
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
}

/// An abstract object is either a tracked or an untracked memory object.
/// In the untracked case we still track whether the object may contain pointers to other objects.
/// This way we do not necessarily need to invalidate all abstract objects
/// if a pointer contained in an untracked object is used for a memory write.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
enum AbstractObject {
    Untracked(BTreeSet<AbstractIdentifier>),
    Memory(AbstractObjectInfo),
}

impl AbstractObject {
    pub fn new(type_: ObjectType, address_bitsize: BitSize) -> AbstractObject {
        Self::Memory(AbstractObjectInfo {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: Some(ObjectState::Alive),
            type_: Some(type_),
            memory: MemRegion::new(address_bitsize),
        })
    }

    pub fn get_value(&self, offset: Bitvector, bitsize: BitSize) -> Data {
        if let Self::Memory(object_info) = self {
            object_info.get_value(offset, bitsize)
        } else {
            Data::new_top(bitsize)
        }
    }

    pub fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Untracked(set1), Self::Untracked(set2)) => {
                Self::Untracked(set1.union(set2).cloned().collect())
            }
            (Self::Untracked(untracked), Self::Memory(memory))
            | (Self::Memory(memory), Self::Untracked(untracked)) => {
                Self::Untracked(untracked.union(&memory.pointer_targets).cloned().collect())
            }
            (Self::Memory(left), Self::Memory(right)) => Self::Memory(left.merge(right)),
        }
    }

    pub fn set_value(&mut self, value: Data, offset: BitvectorDomain) -> Result<(), Error> {
        match self {
            Self::Untracked(target_list) => {
                if let Data::Pointer(ref pointer) = value {
                    target_list.extend(
                        pointer
                            .iter_targets()
                            .map(|(abstract_id, _offset)| abstract_id.clone()),
                    )
                };
            }
            Self::Memory(memory_object) => {
                memory_object.set_value(value, offset)?;
            }
        };
        Ok(())
    }

    pub fn get_all_possible_pointer_targets(&self) -> BTreeSet<AbstractIdentifier> {
        match self {
            Self::Untracked(targets) => targets.clone(),
            Self::Memory(memory) => memory.get_all_possible_pointer_targets(),
        }
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        match self {
            Self::Untracked(id_set) => {
                if id_set.get(old_id).is_some() {
                    id_set.remove(old_id);
                    id_set.insert(new_id.clone());
                }
            }
            Self::Memory(mem_object) => {
                mem_object.replace_abstract_id(old_id, new_id, offset_adjustment);
            }
        }
    }

    pub fn get_referenced_ids(&self) -> BTreeSet<AbstractIdentifier> {
        match self {
            Self::Untracked(ids) => ids.clone(),
            Self::Memory(object_info) => object_info.pointer_targets.clone(),
        }
    }

    pub fn set_state(&mut self, new_state: Option<ObjectState>) {
        if let Self::Memory(object_info) = self {
            object_info.set_state(new_state)
        }
    }
}

/// The abstract object info contains all information that we track for an abstract object.
///
/// Some noteworthy properties:
/// - The field *is_unique* indicates whether the object is the union of several memory objects
/// - The *state* indicates whether the object is still alive or not.
///   This can be used to detect "use after free" bugs.
/// - Many fields are wrapped in Option<_> to indicate whether the property is known or not.
/// - The field pointer_targets is a (coarse) upper approximation of all possible targets
///   for which pointers may exist inside the memory region.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
struct AbstractObjectInfo {
    pointer_targets: BTreeSet<AbstractIdentifier>,
    is_unique: bool,
    state: Option<ObjectState>,
    type_: Option<ObjectType>,
    memory: MemRegion<Data>,
}

impl AbstractObjectInfo {
    fn get_value(&self, offset: Bitvector, bitsize: BitSize) -> Data {
        // TODO: This function does not check whether a data read is "sound", e.g. that the offset is inside the object.
        // Make sure that this is checked somewhere!
        assert_eq!(bitsize % 8, 0);
        self.memory.get(offset, (bitsize / 8) as u64)
    }

    fn set_value(&mut self, value: Data, offset: BitvectorDomain) -> Result<(), Error> {
        if let Data::Pointer(ref pointer) = value {
            self.pointer_targets.extend(
                pointer
                    .iter_targets()
                    .map(|(abstract_id, _offset)| abstract_id.clone()),
            )
        };
        if let BitvectorDomain::Value(ref concrete_offset) = offset {
            if self.is_unique {
                self.memory.add(value, concrete_offset.clone());
            } else {
                let merged_value = self
                    .memory
                    .get(concrete_offset.clone(), (value.bitsize() / 8) as u64)
                    .merge(&value);
                self.memory.add(merged_value, concrete_offset.clone());
            };
        } else {
            self.memory = MemRegion::new(self.memory.get_address_bitsize());
        }
        return Ok(());
    }

    fn get_all_possible_pointer_targets(&self) -> BTreeSet<AbstractIdentifier> {
        let mut targets = self.pointer_targets.clone();
        for elem in self.memory.iter_values() {
            if let Data::Pointer(pointer) = elem {
                for (id, _) in pointer.iter_targets() {
                    targets.insert(id.clone());
                }
            };
        }
        return targets;
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        for elem in self.memory.iter_values_mut() {
            elem.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        if self.pointer_targets.get(&old_id).is_some() {
            self.pointer_targets.remove(&old_id);
            self.pointer_targets.insert(new_id.clone());
        }
    }

    pub fn set_state(&mut self, new_state: Option<ObjectState>) {
        if self.is_unique {
            self.state = new_state;
        } else {
            if self.state != new_state {
                self.state = None;
            } // else don't change the state
        }
    }
}

impl AbstractDomain for AbstractObjectInfo {
    fn top(&self) -> Self {
        AbstractObjectInfo {
            pointer_targets: BTreeSet::new(),
            is_unique: false,
            state: None,
            type_: None,
            memory: MemRegion::new(self.memory.get_address_bitsize()),
        }
    }

    fn merge(&self, other: &Self) -> Self {
        AbstractObjectInfo {
            pointer_targets: self
                .pointer_targets
                .union(&other.pointer_targets)
                .cloned()
                .collect(),
            is_unique: self.is_unique && other.is_unique,
            state: same_or_none(&self.state, &other.state),
            type_: same_or_none(&self.type_, &other.type_),
            memory: self.memory.merge(&other.memory),
        }
    }
}

fn same_or_none<T: Eq + Clone>(left: &Option<T>, right: &Option<T>) -> Option<T> {
    if left.as_ref()? == right.as_ref()? {
        Some(left.as_ref().unwrap().clone())
    } else {
        None
    }
}

fn minimum_or_none(left: &Option<Bitvector>, right: &Option<Bitvector>) -> Option<Bitvector> {
    if let (Some(left), Some(right)) = (left, right) {
        if left.checked_slt(&right).unwrap() {
            Some(left.clone())
        } else {
            Some(right.clone())
        }
    } else {
        None
    }
}

fn maximum_or_none(left: &Option<Bitvector>, right: &Option<Bitvector>) -> Option<Bitvector> {
    if let (Some(left), Some(right)) = (left, right) {
        if left.checked_sgt(right).unwrap() {
            Some(left.clone())
        } else {
            Some(right.clone())
        }
    } else {
        None
    }
}

/// An object is either a stack or a heap object.
/// TODO: add a type for tracking for global variables!
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ObjectType {
    Stack,
    Heap,
}

/// An object is either alive or dangling (because the memory was freed or a function return invalidated the stack frame).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ObjectState {
    Alive,
    Dangling,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_abstract_object() -> AbstractObject {
        let obj_info = AbstractObjectInfo {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: Some(ObjectState::Alive),
            type_: Some(ObjectType::Heap),
            memory: MemRegion::new(64),
        };
        AbstractObject::Memory(obj_info)
    }

    fn new_data(number: i64) -> Data {
        Data::Value(bv(number))
    }

    fn bv(number: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(number))
    }

    #[test]
    fn abstract_object() {
        let mut object = new_abstract_object();
        let three = new_data(3);
        let offset = bv(-15);
        object.set_value(three, offset).unwrap();
        assert_eq!(
            object.get_value(Bitvector::from_i64(-16), 64),
            Data::Top(64)
        );
        assert_eq!(object.get_value(Bitvector::from_i64(-15), 64), new_data(3));
        object.set_value(new_data(4), bv(-12)).unwrap();
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), 64),
            Data::Top(64)
        );

        let mut other_object = new_abstract_object();
        object.set_value(new_data(0), bv(0)).unwrap();
        other_object.set_value(new_data(0), bv(0)).unwrap();
        let merged_object = object.merge(&other_object);
        assert_eq!(
            merged_object.get_value(Bitvector::from_i64(-12), 64),
            Data::Top(64)
        );
        assert_eq!(
            merged_object.get_value(Bitvector::from_i64(0), 64),
            new_data(0)
        );
    }
}
