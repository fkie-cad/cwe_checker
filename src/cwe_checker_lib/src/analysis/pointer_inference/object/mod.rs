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
    /// Is the object alive or already destroyed
    state: ObjectState,
    /// Is the object a stack frame or a heap object
    type_: Option<ObjectType>,
    /// The actual content of the memory object
    memory: MemRegion<Data>,
    /// The smallest index still contained in the memory region.
    /// A `Top` value represents an unknown bound.
    /// The bound is not enforced, i.e. reading and writing to indices violating the bound is still allowed.
    lower_index_bound: BitvectorDomain,
    /// The largest index still contained in the memory region.
    /// A `Top` value represents an unknown bound.
    /// The bound is not enforced, i.e. reading and writing to indices violating the bound is still allowed.
    upper_index_bound: BitvectorDomain,
}

/// An object is either a stack or a heap object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ObjectType {
    /// A stack object, i.e. the stack frame of a function.
    Stack,
    /// A memory object located on the heap.
    Heap,
}

/// An object is either alive or dangling (because the memory was freed or a function return invalidated the stack frame).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ObjectState {
    /// The object is alive.
    Alive,
    /// The object is dangling, i.e. the memory has been freed already.
    Dangling,
    /// The state of the object is unknown (due to merging different object states).
    Unknown,
    /// The object was referenced in an "use-after-free" or "double-free" CWE-warning.
    /// This state is meant to be temporary to prevent obvious subsequent CWE-warnings with the same root cause.
    Flagged,
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
    pub fn new(type_: ObjectType, address_bytesize: ByteSize) -> AbstractObject {
        let inner = Inner {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: ObjectState::Alive,
            type_: Some(type_),
            memory: MemRegion::new(address_bytesize),
            lower_index_bound: BitvectorDomain::Top(address_bytesize),
            upper_index_bound: BitvectorDomain::Top(address_bytesize),
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

    /// Set the lower index bound that is still considered to be contained in the abstract object.
    pub fn set_lower_index_bound(&mut self, lower_bound: BitvectorDomain) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.lower_index_bound = lower_bound;
    }

    /// Set the upper index bound that is still considered to be contained in the abstract object.
    pub fn set_upper_index_bound(&mut self, upper_bound: BitvectorDomain) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.upper_index_bound = upper_bound;
    }

    /// Get the state of the memory object.
    pub fn get_state(&self) -> ObjectState {
        self.inner.state
    }

    /// If `self.is_unique()==true`, set the state of the object. Else merge the new state with the old.
    pub fn set_state(&mut self, new_state: ObjectState) {
        let inner = Arc::make_mut(&mut self.inner);
        if inner.is_unique {
            inner.state = new_state;
        } else {
            inner.state = inner.state.merge(new_state);
        }
    }

    /// Get the type of the memory object.
    pub fn get_object_type(&self) -> Option<ObjectType> {
        self.inner.type_
    }

    /// Mark the memory object as freed.
    /// Returns an error if a possible double free is detected
    /// or the memory object may not be a heap object.
    pub fn mark_as_freed(&mut self) -> Result<(), Error> {
        if self.inner.type_ != Some(ObjectType::Heap) {
            self.set_state(ObjectState::Flagged);
            return Err(anyhow!("Free operation on possibly non-heap memory object"));
        }
        let inner = Arc::make_mut(&mut self.inner);
        match (inner.is_unique, inner.state) {
            (true, ObjectState::Alive) | (true, ObjectState::Flagged) => {
                inner.state = ObjectState::Dangling;
                Ok(())
            }
            (false, ObjectState::Flagged) => {
                inner.state = ObjectState::Unknown;
                Ok(())
            }
            (true, _) | (false, ObjectState::Dangling) => {
                inner.state = ObjectState::Flagged;
                Err(anyhow!("Object may already have been freed"))
            }
            (false, _) => {
                inner.state = ObjectState::Unknown;
                Ok(())
            }
        }
    }

    /// Mark the memory object as possibly (but not definitely) freed.
    /// Returns an error if the object was definitely freed before
    /// or if the object may not be a heap object.
    pub fn mark_as_maybe_freed(&mut self) -> Result<(), Error> {
        if self.inner.type_ != Some(ObjectType::Heap) {
            self.set_state(ObjectState::Flagged);
            return Err(anyhow!("Free operation on possibly non-heap memory object"));
        }
        let inner = Arc::make_mut(&mut self.inner);
        match inner.state {
            ObjectState::Dangling => {
                inner.state = ObjectState::Flagged;
                Err(anyhow!("Object may already have been freed"))
            }
            _ => {
                inner.state = ObjectState::Unknown;
                Ok(())
            }
        }
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
                state: self.inner.state.merge(other.inner.state),
                type_: same_or_none(&self.inner.type_, &other.inner.type_),
                memory: self.inner.memory.merge(&other.inner.memory),
                lower_index_bound: self
                    .inner
                    .lower_index_bound
                    .merge(&other.inner.lower_index_bound),
                upper_index_bound: self
                    .inner
                    .upper_index_bound
                    .merge(&other.inner.upper_index_bound),
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
                "state".to_string(),
                serde_json::Value::String(format!("{:?}", self.inner.state)),
            ),
            (
                "type".to_string(),
                serde_json::Value::String(format!("{:?}", self.inner.type_)),
            ),
            (
                "lower_index_bound".to_string(),
                serde_json::Value::String(format!("{}", self.inner.lower_index_bound)),
            ),
            (
                "upper_index_bound".to_string(),
                serde_json::Value::String(format!("{}", self.inner.upper_index_bound)),
            ),
        ];
        let memory = self
            .inner
            .memory
            .iter()
            .map(|(index, value)| (format!("{}", index), value.to_json_compact()));
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

impl ObjectState {
    /// Merge two object states.
    /// If one of the two states is `Flagged`, then the resulting state is the other object state.
    pub fn merge(self, other: Self) -> Self {
        use ObjectState::*;
        match (self, other) {
            (Flagged, state) | (state, Flagged) => state,
            (Unknown, _) | (_, Unknown) => Unknown,
            (Alive, Alive) => Alive,
            (Dangling, Dangling) => Dangling,
            (Alive, Dangling) | (Dangling, Alive) => Unknown,
        }
    }
}

#[cfg(test)]
mod tests;
