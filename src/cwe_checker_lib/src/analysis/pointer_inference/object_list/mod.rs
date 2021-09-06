use super::object::*;
use super::{Data, ValueDomain};
use crate::prelude::*;
use crate::{abstract_domain::*, utils::binary::RuntimeMemoryImage};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod cwe_helpers;
mod list_manipulation;
mod id_manipulation;

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

    /// Get the value at a given address.
    /// If the address is not unique, merge the value of all possible addresses.
    ///
    /// This function only checks for relative targets and not for absolute addresses.
    /// If the address does not contain any relative targets an empty value is returned.
    pub fn get_value(&self, address: &Data, size: ByteSize) -> Data {
        let mut merged_value = Data::new_empty(size);
        for (id, offset_pointer) in address.get_relative_values() {
            if let Some((object, offset_identifier)) = self.objects.get(id) {
                let offset = offset_pointer.clone() + offset_identifier.clone();
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

    /// Set the value at a given address.
    ///
    /// If the address has more than one target,
    /// we merge-write the value to all targets.
    pub fn set_value(&mut self, pointer: Data, value: Data) -> Result<(), Error> {
        let targets = pointer.get_relative_values();
        match targets.len() {
            0 => Ok(()),
            1 => {
                let (id, pointer_offset) = targets.iter().next().unwrap();
                let (object, id_offset) = self.objects.get_mut(id).unwrap();
                let adjusted_offset = pointer_offset.clone() + id_offset.clone();
                object.set_value(value, &adjusted_offset)
            }
            _ => {
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
            Some((object, _)) => Ok(object.is_unique()),
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
mod tests;
