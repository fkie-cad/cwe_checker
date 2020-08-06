use super::Data;
use crate::abstract_domain::*;
use crate::bil::Bitvector;
use crate::prelude::*;
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::ops::DerefMut;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Deref)]
#[deref(forward)]
pub struct AbstractObject(Arc<AbstractObjectInfo>);

impl DerefMut for AbstractObject {
    fn deref_mut(&mut self) -> &mut AbstractObjectInfo {
        Arc::make_mut(&mut self.0)
    }
}

impl AbstractObject {
    pub fn new(type_: ObjectType, address_bitsize: BitSize) -> AbstractObject {
        AbstractObject(Arc::new(AbstractObjectInfo::new(type_, address_bitsize)))
    }

    pub fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            AbstractObject(Arc::new(self.0.merge(other)))
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
pub struct AbstractObjectInfo {
    pointer_targets: BTreeSet<AbstractIdentifier>,
    pub is_unique: bool,
    state: Option<ObjectState>,
    type_: Option<ObjectType>,
    memory: MemRegion<Data>,
}

impl AbstractObjectInfo {
    pub fn new(type_: ObjectType, address_bitsize: BitSize) -> AbstractObjectInfo {
        AbstractObjectInfo {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: Some(ObjectState::Alive),
            type_: Some(type_),
            memory: MemRegion::new(address_bitsize),
        }
    }

    pub fn get_value(&self, offset: Bitvector, bitsize: BitSize) -> Data {
        // TODO: This function does not check whether a data read is "sound", e.g. that the offset is inside the object.
        // Make sure that this is checked somewhere!
        assert_eq!(bitsize % 8, 0);
        self.memory.get(offset, (bitsize / 8) as u64)
    }

    pub fn set_value(&mut self, value: Data, offset: BitvectorDomain) -> Result<(), Error> {
        if let Data::Pointer(ref pointer) = value {
            self.pointer_targets.extend(pointer.ids().cloned());
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
        Ok(())
    }

    /// Merge `value` at position `offset` with the value currently saved at that position.
    pub fn merge_value(&mut self, value: Data, offset: BitvectorDomain) {
        if let Data::Pointer(ref pointer) = value {
            self.pointer_targets.extend(pointer.ids().cloned());
        };
        if let BitvectorDomain::Value(ref concrete_offset) = offset {
            let merged_value = self
                .memory
                .get(concrete_offset.clone(), (value.bitsize() / 8) as u64)
                .merge(&value);
            self.memory.add(merged_value, concrete_offset.clone());
        } else {
            self.memory = MemRegion::new(self.memory.get_address_bitsize());
        }
    }

    pub fn get_referenced_ids(&self) -> &BTreeSet<AbstractIdentifier> {
        &self.pointer_targets
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offsets.
    /// This is needed to adjust stack pointers on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        for elem in self.memory.values_mut() {
            elem.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        self.memory.clear_top_values();
        if self.pointer_targets.get(&old_id).is_some() {
            self.pointer_targets.remove(&old_id);
            self.pointer_targets.insert(new_id.clone());
        }
    }

    pub fn set_state(&mut self, new_state: Option<ObjectState>) {
        if self.is_unique {
            self.state = new_state;
        } else if self.state != new_state {
            self.state = None;
        } // else don't change the state
    }

    /// Remove the provided IDs from the target lists of all pointers in the memory object.
    /// Also remove them from the pointer_targets list.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        self.pointer_targets = self
            .pointer_targets
            .difference(ids_to_remove)
            .cloned()
            .collect();
        for value in self.memory.values_mut() {
            value.remove_ids(ids_to_remove); // TODO: This may leave *Top* values in the memory object. Remove them.
        }
        self.memory.clear_top_values()
    }

    pub fn get_state(&self) -> Option<ObjectState> {
        self.state
    }

    /// Invalidates all memory and adds the `additional_targets` to the pointer targets.
    /// Represents the effect of unknown write instructions to the object
    /// which may include writing pointers to targets from the `additional_targets` set to the object.
    pub fn assume_arbitrary_writes(&mut self, additional_targets: &BTreeSet<AbstractIdentifier>) {
        self.memory = MemRegion::new(self.memory.get_address_bitsize());
        self.pointer_targets
            .extend(additional_targets.iter().cloned());
    }
}

impl AbstractDomain for AbstractObjectInfo {
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

    /// The domain has no *Top* element, thus this function always returns false.
    fn is_top(&self) -> bool {
        false
    }
}

impl AbstractObjectInfo {
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut elements = Vec::new();
        elements.push((
            "is_unique".to_string(),
            serde_json::Value::String(format!("{}", self.is_unique)),
        ));
        elements.push((
            "state".to_string(),
            serde_json::Value::String(format!("{:?}", self.state)),
        ));
        elements.push((
            "type".to_string(),
            serde_json::Value::String(format!("{:?}", self.type_)),
        ));
        let memory = self
            .memory
            .iter()
            .map(|(index, value)| (format!("{}", index), value.to_json_compact()));
        elements.push((
            "memory".to_string(),
            serde_json::Value::Object(serde_json::Map::from_iter(memory)),
        ));
        serde_json::Value::Object(serde_json::Map::from_iter(elements.into_iter()))
    }
}

fn same_or_none<T: Eq + Clone>(left: &Option<T>, right: &Option<T>) -> Option<T> {
    if left.as_ref()? == right.as_ref()? {
        Some(left.as_ref().unwrap().clone())
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
        AbstractObject(Arc::new(obj_info))
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
