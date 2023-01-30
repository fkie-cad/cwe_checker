use super::object::*;
use super::Data;
use crate::abstract_domain::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod id_manipulation;
mod list_manipulation;

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that there is exactly one abstract identifier pointing to it.
/// However, an abstract object itself can be marked as non-unique
/// to indicate that it may represent more than one actual memory object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    /// The abstract objects.
    objects: BTreeMap<AbstractIdentifier, AbstractObject>,
}

impl AbstractObjectList {
    /// Create a new abstract object list with one abstract object corresponding to the stack
    /// and one abstract object corresponding to global memory
    ///
    /// The offset into the stack object will be set to zero.
    /// This corresponds to the generic stack state at the start of a function.
    pub fn from_stack_id(
        stack_id: AbstractIdentifier,
        address_bytesize: ByteSize,
    ) -> AbstractObjectList {
        let stack_object = AbstractObject::new(Some(ObjectType::Stack), address_bytesize);
        let global_mem_id = AbstractIdentifier::new(
            stack_id.get_tid().clone(),
            AbstractLocation::GlobalAddress {
                address: 0,
                size: address_bytesize,
            },
        );
        let global_mem_object = AbstractObject::new(Some(ObjectType::GlobalMem), address_bytesize);
        let objects =
            BTreeMap::from([(stack_id, stack_object), (global_mem_id, global_mem_object)]);
        AbstractObjectList { objects }
    }

    /// Get the value at a given address.
    /// If the address is not unique, merge the value of all possible addresses.
    ///
    /// This function only checks for relative targets and not for absolute addresses.
    /// If the address does not contain any relative targets an empty value is returned.
    pub fn get_value(&self, address: &Data, size: ByteSize) -> Data {
        let mut merged_value = Data::new_empty(size);
        for (id, offset) in address.get_relative_values() {
            if let Some(object) = self.objects.get(id) {
                if let Ok(concrete_offset) = offset.try_to_bitvec() {
                    let value = object.get_value(concrete_offset, size);
                    merged_value = merged_value.merge(&value);
                } else {
                    merged_value.set_contains_top_flag();
                }
            } else {
                merged_value.set_contains_top_flag();
            }
        }
        if address.contains_top() {
            merged_value.set_contains_top_flag();
        }
        merged_value
    }

    /// Get a mutable reference to the object with the given abstract ID.
    pub fn get_object_mut(&mut self, id: &AbstractIdentifier) -> Option<&mut AbstractObject> {
        self.objects.get_mut(id)
    }

    /// Set the value at a given address.
    ///
    /// If the address has more than one target,
    /// we merge-write the value to all targets.
    pub fn set_value(&mut self, pointer: Data, value: Data) -> Result<(), Error> {
        if let Some((id, offset)) = pointer.get_if_unique_target() {
            let object = self
                .objects
                .get_mut(id)
                .ok_or_else(|| anyhow!("Abstract object does not exist."))?;
            object.set_value(value, offset)
        } else {
            // There may be more than one object that the pointer may write to.
            // We merge-write to all possible targets
            for (id, offset) in pointer.get_relative_values() {
                let object = self
                    .objects
                    .get_mut(id)
                    .ok_or_else(|| anyhow!("Abstract object does not exist."))?;
                object.merge_value(value.clone(), offset);
            }
            Ok(())
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
        if let Some(object) = self.objects.get_mut(object_id) {
            object.assume_arbitrary_writes(new_possible_reference_targets);
        }
    }

    /// Return the object type of a memory object.
    /// Returns an error if no object with the given ID is contained in the object list.
    pub fn get_object_type(
        &self,
        object_id: &AbstractIdentifier,
    ) -> Result<Option<ObjectType>, ()> {
        match self.objects.get(object_id) {
            Some(object) => Ok(object.get_object_type()),
            None => Err(()),
        }
    }

    /// Returns `true` if the object corresponding to the given ID represents an unique object
    /// and `false` if it may represent more than one object (e.g. several array elements).
    /// Returns an error if the ID is not contained in the object list.
    pub fn is_unique_object(&self, object_id: &AbstractIdentifier) -> Result<bool, Error> {
        match self.objects.get(object_id) {
            Some(object) => Ok(object.is_unique()),
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
        for (id, other_object) in other.objects.iter() {
            if let Some(object) = merged_objects.get_mut(id) {
                *object = object.merge(other_object);
            } else {
                merged_objects.insert(id.clone(), other_object.clone());
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
        for (id, object) in self.objects.iter() {
            object_map.insert(format!("{id}"), object.to_json_compact());
        }
        Value::Object(object_map)
    }
}

#[cfg(test)]
mod tests;
