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

/// A wrapper struct wrapping `AbstractObjectInfo` in an `Arc`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Deref)]
#[deref(forward)]
pub struct AbstractObject(Arc<AbstractObjectInfo>);

impl DerefMut for AbstractObject {
    fn deref_mut(&mut self) -> &mut AbstractObjectInfo {
        Arc::make_mut(&mut self.0)
    }
}

impl AbstractObject {
    /// Create a new abstract object with given object type and address bitsize.
    pub fn new(type_: ObjectType, address_bytesize: ByteSize) -> AbstractObject {
        AbstractObject(Arc::new(AbstractObjectInfo::new(type_, address_bytesize)))
    }

    /// Short-circuits the `AbstractObjectInfo::merge` function if `self==other`.
    pub fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            AbstractObject(Arc::new(self.0.merge(other)))
        }
    }
}

/// The abstract object info contains all information that we track for an abstract object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectInfo {
    /// An upper approximation of all possible targets for which pointers may exist inside the memory region.
    pointer_targets: BTreeSet<AbstractIdentifier>,
    /// Tracks whether this may represent more than one actual memory object.
    pub is_unique: bool,
    /// Is the object alive or already destroyed
    state: Option<ObjectState>,
    /// Is the object a stack frame or a heap object
    type_: Option<ObjectType>,
    /// The actual content of the memory object
    memory: MemRegion<Data>,
}

impl AbstractObjectInfo {
    /// Create a new abstract object with known object type and address bitsize
    pub fn new(type_: ObjectType, address_bytesize: ByteSize) -> AbstractObjectInfo {
        AbstractObjectInfo {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: Some(ObjectState::Alive),
            type_: Some(type_),
            memory: MemRegion::new(address_bytesize),
        }
    }

    /// Read the value at the given offset of the given size (in bits, not bytes) inside the memory region.
    pub fn get_value(&self, offset: Bitvector, bytesize: ByteSize) -> Data {
        self.memory.get(offset, bytesize)
    }

    /// Write a value at the given offset to the memory region.
    ///
    /// If the abstract object is not unique (i.e. may represent more than one actual object),
    /// merge the old value at the given offset with the new value.
    pub fn set_value(&mut self, value: Data, offset: &BitvectorDomain) -> Result<(), Error> {
        if let Data::Pointer(ref pointer) = value {
            self.pointer_targets.extend(pointer.ids().cloned());
        };
        if let BitvectorDomain::Value(ref concrete_offset) = offset {
            if self.is_unique {
                self.memory.add(value, concrete_offset.clone());
            } else {
                let merged_value = self
                    .memory
                    .get(concrete_offset.clone(), value.bytesize())
                    .merge(&value);
                self.memory.add(merged_value, concrete_offset.clone());
            };
        } else {
            self.memory = MemRegion::new(self.memory.get_address_bytesize());
        }
        Ok(())
    }

    /// Merge `value` at position `offset` with the value currently saved at that position.
    pub fn merge_value(&mut self, value: Data, offset: &BitvectorDomain) {
        if let Data::Pointer(ref pointer) = value {
            self.pointer_targets.extend(pointer.ids().cloned());
        };
        if let BitvectorDomain::Value(ref concrete_offset) = offset {
            let merged_value = self
                .memory
                .get(concrete_offset.clone(), value.bytesize())
                .merge(&value);
            self.memory.add(merged_value, concrete_offset.clone());
        } else {
            self.memory = MemRegion::new(self.memory.get_address_bytesize());
        }
    }

    /// Get all abstract IDs that the object may contain pointers to.
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

    /// If `self.is_unique==true`, set the state of the object. Else merge the new state with the old.
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
            value.remove_ids(ids_to_remove);
        }
        self.memory.clear_top_values(); // In case the previous operation left *Top* values in the memory struct.
    }

    /// Get the state of the memory object.
    pub fn get_state(&self) -> Option<ObjectState> {
        self.state
    }

    /// Get the type of the memory object.
    pub fn get_object_type(&self) -> Option<ObjectType> {
        self.type_
    }

    /// Invalidates all memory and adds the `additional_targets` to the pointer targets.
    /// Represents the effect of unknown write instructions to the object
    /// which may include writing pointers to targets from the `additional_targets` set to the object.
    pub fn assume_arbitrary_writes(&mut self, additional_targets: &BTreeSet<AbstractIdentifier>) {
        self.memory = MemRegion::new(self.memory.get_address_bytesize());
        self.pointer_targets
            .extend(additional_targets.iter().cloned());
    }

    /// Mark the memory object as freed.
    /// Returns an error if a possible double free is detected
    /// or the memory object may not be a heap object.
    pub fn mark_as_freed(&mut self) -> Result<(), Error> {
        if self.type_ != Some(ObjectType::Heap) {
            self.set_state(Some(ObjectState::Dangling));
            return Err(anyhow!("Free operation on possibly non-heap memory object"));
        }
        match (self.is_unique, self.state) {
            (true, Some(ObjectState::Alive)) => {
                self.state = Some(ObjectState::Dangling);
                Ok(())
            }
            (true, _) | (false, Some(ObjectState::Dangling)) => {
                self.state = Some(ObjectState::Dangling);
                Err(anyhow!("Object may already have been freed"))
            }
            (false, _) => {
                self.state = None;
                Ok(())
            }
        }
    }

    /// Mark the memory object as possibly (but not definitely) freed.
    /// Returns an error if the object was definitely freed before
    /// or if the object may not be a heap object.
    pub fn mark_as_maybe_freed(&mut self) -> Result<(), Error> {
        if self.type_ != Some(ObjectType::Heap) {
            self.set_state(Some(ObjectState::Dangling));
            return Err(anyhow!("Free operation on possibly non-heap memory object"));
        }
        if self.state != Some(ObjectState::Dangling) {
            self.state = None;
            Ok(())
        } else {
            Err(anyhow!("Object may already have been freed"))
        }
    }
}

impl AbstractDomain for AbstractObjectInfo {
    /// Merge two abstract objects
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
    /// Get a more compact json-representation of the abstract object.
    /// Intended for pretty printing, not useable for serialization/deserialization.
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

/// Helper function for merging two `Option<T>` values (merging to `None` if they are not equal).
fn same_or_none<T: Eq + Clone>(left: &Option<T>, right: &Option<T>) -> Option<T> {
    if left.as_ref()? == right.as_ref()? {
        Some(left.as_ref().unwrap().clone())
    } else {
        None
    }
}

/// An object is either a stack or a heap object.
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
            memory: MemRegion::new(ByteSize::new(8)),
        };
        AbstractObject(Arc::new(obj_info))
    }

    fn new_data(number: i64) -> Data {
        Data::Value(bv(number))
    }

    fn bv(number: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(number))
    }

    fn new_id(tid: &str, reg_name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new(tid),
            AbstractLocation::Register(reg_name.into(), ByteSize::new(8)),
        )
    }

    #[test]
    fn abstract_object() {
        let mut object = new_abstract_object();
        let three = new_data(3);
        let offset = bv(-15);
        object.set_value(three, &offset).unwrap();
        assert_eq!(
            object.get_value(Bitvector::from_i64(-16), ByteSize::new(8)),
            Data::Top(ByteSize::new(8))
        );
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            new_data(3)
        );
        object.set_value(new_data(4), &bv(-12)).unwrap();
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            Data::Top(ByteSize::new(8))
        );
        object.merge_value(new_data(5), &bv(-12));
        assert_eq!(
            object.get_value(Bitvector::from_i64(-12), ByteSize::new(8)),
            Data::Value(BitvectorDomain::new_top(ByteSize::new(8)))
        );

        let mut other_object = new_abstract_object();
        object.set_value(new_data(0), &bv(0)).unwrap();
        other_object.set_value(new_data(0), &bv(0)).unwrap();
        let merged_object = object.merge(&other_object);
        assert_eq!(
            merged_object.get_value(Bitvector::from_i64(-12), ByteSize::new(8)),
            Data::Top(ByteSize::new(8))
        );
        assert_eq!(
            merged_object.get_value(Bitvector::from_i64(0), ByteSize::new(8)),
            new_data(0)
        );
    }

    #[test]
    fn replace_id() {
        use std::collections::BTreeMap;
        let mut object = new_abstract_object();
        let mut target_map = BTreeMap::new();
        target_map.insert(new_id("time_1", "RAX"), bv(20));
        target_map.insert(new_id("time_234", "RAX"), bv(30));
        target_map.insert(new_id("time_1", "RBX"), bv(40));
        let pointer = PointerDomain::with_targets(target_map.clone());
        object.set_value(pointer.into(), &bv(-15)).unwrap();
        assert_eq!(object.get_referenced_ids().len(), 3);

        object.replace_abstract_id(
            &new_id("time_1", "RAX"),
            &new_id("time_234", "RAX"),
            &bv(10),
        );
        target_map.remove(&new_id("time_1", "RAX"));
        let modified_pointer = PointerDomain::with_targets(target_map);
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            modified_pointer.into()
        );

        object.replace_abstract_id(
            &new_id("time_1", "RBX"),
            &new_id("time_234", "RBX"),
            &bv(10),
        );
        let mut target_map = BTreeMap::new();
        target_map.insert(new_id("time_234", "RAX"), bv(30));
        target_map.insert(new_id("time_234", "RBX"), bv(50));
        let modified_pointer = PointerDomain::with_targets(target_map);
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            modified_pointer.into()
        );
    }

    #[test]
    fn remove_ids() {
        use std::collections::BTreeMap;
        let mut object = new_abstract_object();
        let mut target_map = BTreeMap::new();
        target_map.insert(new_id("time_1", "RAX"), bv(20));
        target_map.insert(new_id("time_234", "RAX"), bv(30));
        target_map.insert(new_id("time_1", "RBX"), bv(40));
        let pointer = PointerDomain::with_targets(target_map.clone());
        object.set_value(pointer.into(), &bv(-15)).unwrap();
        assert_eq!(object.get_referenced_ids().len(), 3);

        let ids_to_remove = vec![new_id("time_1", "RAX"), new_id("time_23", "RBX")]
            .into_iter()
            .collect();
        object.remove_ids(&ids_to_remove);
        assert_eq!(
            object.get_referenced_ids(),
            &vec![new_id("time_234", "RAX"), new_id("time_1", "RBX")]
                .into_iter()
                .collect()
        );
    }
}
