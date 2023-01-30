//! This module contains the definition of the abstract memory object type.

use super::{Data, ValueDomain};
use crate::abstract_domain::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Methods for manipulating abstract IDs contained in an abstract object.
mod id_manipulation;

/// Methods for handling read/write operations on an abstract object.
mod value_access;

/// An abstract object contains all knowledge tracked about a particular memory object.
///
/// In some cases one abstract object can represent more than one actual memory object.
/// This happens for e.g. several memory objects allocated into an array,
/// since we cannot represent every object separately without knowing the exact number of objects
/// (which may be runtime dependent).
///
/// To allow cheap cloning of abstract objects, the actual data is wrapped in an `Arc`.
///
/// Examples of memory objects:
/// * The stack frame of a function
/// * A memory object allocated on the heap
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AbstractObject {
    inner: Arc<Inner>,
}

/// The abstract object info contains all information that we track for an abstract object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
struct Inner {
    /// An upper approximation of all possible targets for which pointers may exist inside the memory region.
    pointer_targets: BTreeSet<AbstractIdentifier>,
    /// Tracks whether this may represent more than one actual memory object.
    is_unique: bool,
    /// Is the object a stack frame, a heap object, or a global memory object.
    type_: Option<ObjectType>,
    /// The actual content of the memory object
    memory: MemRegion<Data>,
}

/// An object can be a stack, a heap, or a global memory object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ObjectType {
    /// A stack object, i.e. the stack frame of a function.
    Stack,
    /// A memory object located on the heap.
    Heap,
    /// A memory oject indicating the global memory space.
    GlobalMem,
}

#[allow(clippy::from_over_into)]
impl std::convert::Into<AbstractObject> for Inner {
    fn into(self) -> AbstractObject {
        AbstractObject {
            inner: Arc::new(self),
        }
    }
}

impl AbstractObject {
    /// Create a new abstract object with given object type and address bytesize.
    pub fn new(type_: Option<ObjectType>, address_bytesize: ByteSize) -> AbstractObject {
        let inner = Inner {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            type_,
            memory: MemRegion::new(address_bytesize),
        };
        inner.into()
    }

    /// Returns `false` if the abstract object may represent more than one object,
    /// e.g. for arrays of objects.
    pub fn is_unique(&self) -> bool {
        self.inner.is_unique
    }

    /// Mark the abstract object as possibly representing more than one actual memory object.
    pub fn mark_as_not_unique(&mut self) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.is_unique = false;
    }

    /// Get the type of the memory object.
    pub fn get_object_type(&self) -> Option<ObjectType> {
        self.inner.type_
    }

    /// Overwrite the values in `self` with those in `other`
    /// under the assumption that the zero offset in `other` corresponds to the offset `offset_other` in `self`.
    ///
    /// If `self` is not a unique memory object or if `offset_other` is not a precisely known offset,
    /// then the function tries to merge `self` and `other`,
    /// since we do not exactly know which values of `self` were overwritten by `other`.
    ///
    /// All values of `self` are marked as possibly overwritten, i.e. `Top`,
    /// but they are only deleted if they intersect a non-`Top` value of `other`.
    /// This approximates the fact that we currently do not track exactly which indices
    /// in `other` were overwritten with a `Top` element and which indices simply were not
    /// accessed at all in `other`.
    pub fn overwrite_with(&mut self, other: &AbstractObject, offset_other: &ValueDomain) {
        if let Ok(obj_offset) = offset_other.try_to_offset() {
            if self.inner.is_unique {
                let inner = Arc::make_mut(&mut self.inner);
                // Overwrite values in the memory region of self with those of other.
                inner.memory.mark_all_values_as_top();
                for (elem_offset, elem) in other.inner.memory.iter() {
                    inner
                        .memory
                        .insert_at_byte_index(elem.clone(), obj_offset + elem_offset);
                }
                // Merge all other properties with those of other.
                inner.is_unique &= other.inner.is_unique;
                inner
                    .pointer_targets
                    .append(&mut other.inner.pointer_targets.clone());
            } else {
                let inner = Arc::make_mut(&mut self.inner);
                let mut other = other.clone();
                let other_inner = Arc::make_mut(&mut other.inner);
                other_inner.memory.add_offset_to_all_indices(obj_offset);

                inner.memory = inner.memory.merge(&other_inner.memory);
                inner.is_unique &= other.inner.is_unique;
                inner
                    .pointer_targets
                    .append(&mut other.inner.pointer_targets.clone());
            }
        } else {
            let inner = Arc::make_mut(&mut self.inner);
            inner.memory.mark_all_values_as_top();
            inner.is_unique &= other.inner.is_unique;
            inner
                .pointer_targets
                .append(&mut other.inner.pointer_targets.clone());
        }
    }

    /// Add an offset to all values contained in the abstract object.
    pub fn add_offset_to_all_indices(&mut self, offset: &ValueDomain) {
        let inner = Arc::make_mut(&mut self.inner);
        if let Ok(offset) = offset.try_to_offset() {
            inner.memory.add_offset_to_all_indices(offset);
        } else {
            inner.memory = MemRegion::new(inner.memory.get_address_bytesize());
        }
    }

    /// Get the memory region abstract domain associated to the memory object.
    pub fn get_mem_region(&self) -> &MemRegion<Data> {
        &self.inner.memory
    }

    /// Overwrite the memory region abstract domain associated to the memory object.
    /// Note that this function does not update the list of known pointer targets accordingly!
    pub fn overwrite_mem_region(&mut self, new_memory_region: MemRegion<Data>) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.memory = new_memory_region;
    }

    /// Add IDs to the list of pointer targets for the memory object.
    pub fn add_ids_to_pointer_targets(&mut self, mut ids_to_add: BTreeSet<AbstractIdentifier>) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.pointer_targets.append(&mut ids_to_add);
    }
}

impl AbstractDomain for AbstractObject {
    /// Merge two abstract objects
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            Inner {
                pointer_targets: self
                    .inner
                    .pointer_targets
                    .union(&other.inner.pointer_targets)
                    .cloned()
                    .collect(),
                is_unique: self.inner.is_unique && other.inner.is_unique,
                type_: same_or_none(&self.inner.type_, &other.inner.type_),
                memory: self.inner.memory.merge(&other.inner.memory),
            }
            .into()
        }
    }

    /// The domain has no *Top* element, thus this function always returns false.
    fn is_top(&self) -> bool {
        false
    }
}

impl AbstractObject {
    /// Get a more compact json-representation of the abstract object.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut elements = vec![
            (
                "is_unique".to_string(),
                serde_json::Value::String(format!("{}", self.inner.is_unique)),
            ),
            (
                "type".to_string(),
                serde_json::Value::String(format!("{:?}", self.inner.type_)),
            ),
        ];
        let memory = self
            .inner
            .memory
            .iter()
            .map(|(index, value)| (format!("{index}"), value.to_json_compact()));
        elements.push((
            "memory".to_string(),
            serde_json::Value::Object(memory.collect()),
        ));
        serde_json::Value::Object(elements.into_iter().collect())
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

#[cfg(test)]
mod tests;
