use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use crate::analysis::abstract_domain::*;
use crate::analysis::mem_region::MemRegion;
use crate::bil::Bitvector;
use apint::Width;
use super::data::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use super::identifier::AbstractIdentifier;

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that each pointer can only point to one abstract object.
/// If a pointer may point to two different abstract objects,
/// these two objects will be merged to one object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    identifier: BTreeMap<AbstractIdentifier, (Arc<AbstractObject>, Bitvector)>,
}

impl AbstractObjectList {
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
                    let (abstract_object, offset_identifier) = self.identifier.get(id).unwrap();
                    if let BitvectorDomain::Value(offset_pointer) = offset_pointer_domain {
                        let offset = offset_pointer.clone() + offset_identifier;
                        let value = abstract_object.get_value(offset, size);
                        merged_value = match merged_value {
                            Some(accum) => Some(accum.merge(&value)),
                            None => Some(value)
                        };
                    } else {
                        merged_value = Some(Data::new_top(size));
                        break;
                    }
                };
                merged_value.ok_or(anyhow!("Pointer without targets encountered."))
            }
        }
    }

    pub fn set_value(&mut self, object_id: AbstractIdentifier, value: Data, offset: BitvectorDomain) -> Result<(), Error> {
        let (object, global_offset) = &self.identifier[&object_id];
        let adjusted_offset = offset.bin_op(crate::bil::BinOpType::PLUS, &BitvectorDomain::Value(global_offset.clone()));
        let mut modified_object = object.clone();
        let global_offset = global_offset.clone();
        let result = Arc::make_mut(&mut modified_object).set_value(value, adjusted_offset);
        self.identifier.insert(object_id, (modified_object, global_offset));
        return result;
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_ids = self.identifier.clone();
        for (id, (other_object, other_offset)) in other.identifier.iter() {
            if let Some((object, offset)) = self.identifier.get(id) {
                // The offset of an abstract identifier should never change!
                // TODO: The offset may be always zero in practice. If true, remove it!
                assert_eq!(offset, other_offset);
                merged_ids.insert(id.clone(), (Arc::new(object.merge(other_object)), offset.clone()));
            } else {
                merged_ids.insert(id.clone(), (other_object.clone(), other_offset.clone()));
            }
        };
        AbstractObjectList { identifier: merged_ids }
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
    pub fn get_value(&self, offset: Bitvector, bitsize: BitSize) -> Data {
        if let Self::Memory(object_info) = self {
            object_info.get_value(offset, bitsize)
        } else {
            Data::new_top(bitsize)
        }
    }

    pub fn merge(&self, other: &Self) -> Self {
        match(self, other) {
            (Self::Untracked(set1), Self::Untracked(set2)) => Self::Untracked(set1.union(set2).cloned().collect()),
            (Self::Untracked(untracked), Self::Memory(memory))
            | (Self::Memory(memory), Self::Untracked(untracked)) => Self::Untracked(untracked.union(&memory.pointer_targets).cloned().collect()),
            (Self::Memory(left), Self::Memory(right)) => Self::Memory(left.merge(right))
        }
    }

    pub fn set_value(&mut self, value: Data, offset: BitvectorDomain) -> Result<(), Error> {
        match self {
            Self::Untracked(target_list) => {
                if let Data::Pointer(ref pointer) = value {
                    target_list.extend(pointer.iter_targets().map(|(abstract_id, _offset)| {abstract_id.clone()}) )
                };
            },
            Self::Memory(memory_object) => {
                memory_object.set_value(value, offset)?;
            }
        };
        Ok(())
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
            self.pointer_targets.extend(pointer.iter_targets().map(|(abstract_id, _offset)| {abstract_id.clone()}) )
        };
        if let BitvectorDomain::Value(ref concrete_offset) = offset {
            if self.is_unique {
                self.memory.add(value, concrete_offset.clone());
            } else {
                let merged_value = self.memory.get(concrete_offset.clone(), (value.bitsize() / 8) as u64).merge(&value);
                self.memory.add(merged_value, concrete_offset.clone());
            };
        } else {
            self.memory = MemRegion::new(self.memory.get_address_bitsize());
        }
        return Ok(());
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
            pointer_targets: self.pointer_targets.union(&other.pointer_targets).cloned().collect(),
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
enum ObjectType {
    Stack,
    Heap,
}

/// An object is either alive or dangling (because the memory was freed or a function return invalidated the stack frame).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
enum ObjectState {
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
        assert_eq!(object.get_value(Bitvector::from_i64(-16), 64), Data::Top(64));
        assert_eq!(object.get_value(Bitvector::from_i64(-15), 64), new_data(3));
        object.set_value(new_data(4), bv(-12)).unwrap();
        assert_eq!(object.get_value(Bitvector::from_i64(-15), 64), Data::Top(64));

        let mut other_object = new_abstract_object();
        object.set_value(new_data(0), bv(0)).unwrap();
        other_object.set_value(new_data(0), bv(0)).unwrap();
        let merged_object = object.merge(&other_object);
        assert_eq!(merged_object.get_value(Bitvector::from_i64(-12), 64), Data::Top(64));
        assert_eq!(merged_object.get_value(Bitvector::from_i64(0), 64), new_data(0));
    }
}
