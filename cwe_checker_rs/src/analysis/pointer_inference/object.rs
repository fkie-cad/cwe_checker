use std::collections::{BTreeMap, BTreeSet};
use crate::analysis::abstract_domain::*;
use crate::analysis::mem_region::MemRegion;
use crate::bil::Bitvector;
use apint::Width;
use super::data::*;
use serde::{Serialize, Deserialize};

/// The list of all known abstract objects.
///
/// Each abstract object is unique in the sense that each pointer can only point to one abstract object.
/// If a pointer may point to two different abstract objects,
/// these two objects will be merged to one object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObjectList {
    objects: Vec<AbstractObject>,
    identifier: BTreeMap<AbstractIdentifier, (usize, Bitvector)>,
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

/// The abstract object info contains all information that we track for an abstract object.
///
/// Some noteworthy properties:
/// - The field *is_unique* indicates whether the object is the union of several memory objects
/// - The *state* indicates whether the object is still alive or not.
///   This can be used to detect "use after free" bugs.
/// - Almost all fields are wrapped in Option<_> to indicate whether the property is known or not.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
struct AbstractObjectInfo {
    minimum_address: Option<Bitvector>,
    maximum_address: Option<Bitvector>,
    minimum_write_access: Option<Bitvector>,
    maximum_write_access: Option<Bitvector>,
    pointer_targets: BTreeSet<AbstractIdentifier>,
    is_unique: bool,
    state: Option<ObjectState>,
    type_: Option<ObjectType>,
    memory: MemRegion<Data>,
}

impl AbstractDomain for AbstractObjectInfo {
    fn top(&self) -> Self {
        AbstractObjectInfo {
            minimum_address: None,
            maximum_address: None,
            minimum_write_access: None,
            maximum_write_access: None,
            pointer_targets: BTreeSet::new(),
            is_unique: false,
            state: None,
            type_: None,
            memory: MemRegion::new(self.memory.get_address_bitsize()),
        }
    }

    fn merge(&self, other: &Self) -> Self {
        AbstractObjectInfo {
            minimum_address: minimum_or_none(&self.minimum_address, &other.minimum_address),
            maximum_address: maximum_or_none(&self.maximum_address, &other.maximum_address),
            minimum_write_access: minimum_or_none(&self.minimum_write_access, &other.minimum_write_access),
            maximum_write_access: maximum_or_none(&self.maximum_write_access, &other.maximum_write_access),
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
