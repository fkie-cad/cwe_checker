//! This module contains the definition of the abstract memory object type.

use super::{Data, ValueDomain};
use crate::abstract_domain::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

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

    /// Check whether a memory access to the abstract object at the given offset
    /// and with the given size of the accessed value is contained in the bounds of the memory object.
    /// If `offset` contains more than one possible index value,
    /// then only return `true` if the access is contained in the abstract object for all possible offset values.
    pub fn access_contained_in_bounds(&self, offset: &ValueDomain, size: ByteSize) -> bool {
        if let Ok(offset_interval) = offset.try_to_interval() {
            if let Ok(lower_bound) = self.inner.lower_index_bound.try_to_bitvec() {
                if lower_bound.checked_sgt(&offset_interval.start).unwrap() {
                    return false;
                }
            }
            if let Ok(upper_bound) = self.inner.upper_index_bound.try_to_bitvec() {
                let mut size_as_bitvec = Bitvector::from_u64(u64::from(size));
                match offset.bytesize().cmp(&size_as_bitvec.bytesize()) {
                    std::cmp::Ordering::Less => size_as_bitvec.truncate(offset.bytesize()).unwrap(),
                    std::cmp::Ordering::Greater => {
                        size_as_bitvec.sign_extend(offset.bytesize()).unwrap()
                    }
                    std::cmp::Ordering::Equal => (),
                }
                let max_index = if let Some(val) = offset_interval
                    .end
                    .signed_add_overflow_checked(&size_as_bitvec)
                {
                    val - &Bitvector::one(offset.bytesize().into())
                } else {
                    return false; // The max index already causes an integer overflow
                };
                if upper_bound.checked_slt(&max_index).unwrap() {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Read the value at the given offset of the given size inside the memory region.
    pub fn get_value(&self, offset: Bitvector, bytesize: ByteSize) -> Data {
        self.inner.memory.get(offset, bytesize)
    }

    /// Write a value at the given offset to the memory region.
    ///
    /// If the abstract object is not unique (i.e. may represent more than one actual object),
    /// merge the old value at the given offset with the new value.
    pub fn set_value(&mut self, value: Data, offset: &ValueDomain) -> Result<(), Error> {
        let inner = Arc::make_mut(&mut self.inner);
        inner
            .pointer_targets
            .extend(value.referenced_ids().cloned());
        if let Ok(concrete_offset) = offset.try_to_bitvec() {
            if inner.is_unique {
                inner.memory.add(value, concrete_offset);
            } else {
                let merged_value = inner
                    .memory
                    .get(concrete_offset.clone(), value.bytesize())
                    .merge(&value);
                inner.memory.add(merged_value, concrete_offset);
            };
        } else if let Ok((start, end)) = offset.try_to_offset_interval() {
            inner
                .memory
                .mark_interval_values_as_top(start, end, value.bytesize());
        } else {
            inner.memory.mark_all_values_as_top();
        }
        Ok(())
    }

    /// Merge `value` at position `offset` with the value currently saved at that position.
    pub fn merge_value(&mut self, value: Data, offset: &ValueDomain) {
        let inner = Arc::make_mut(&mut self.inner);
        inner
            .pointer_targets
            .extend(value.referenced_ids().cloned());
        if let Ok(concrete_offset) = offset.try_to_bitvec() {
            let merged_value = inner
                .memory
                .get(concrete_offset.clone(), value.bytesize())
                .merge(&value);
            inner.memory.add(merged_value, concrete_offset);
        } else if let Ok((start, end)) = offset.try_to_offset_interval() {
            inner
                .memory
                .mark_interval_values_as_top(start, end, value.bytesize());
        } else {
            inner.memory.mark_all_values_as_top();
        }
    }

    /// Get all abstract IDs that the object may contain pointers to.
    /// This yields an overapproximation of possible pointer targets.
    pub fn get_referenced_ids_overapproximation(&self) -> &BTreeSet<AbstractIdentifier> {
        &self.inner.pointer_targets
    }

    /// Get all abstract IDs for which the object contains pointers to.
    /// This yields an underapproximation of pointer targets,
    /// since the object may contain pointers that could not be tracked by the analysis.
    pub fn get_referenced_ids_underapproximation(&self) -> BTreeSet<AbstractIdentifier> {
        let mut referenced_ids = BTreeSet::new();
        for data in self.inner.memory.values() {
            referenced_ids.extend(data.referenced_ids().cloned())
        }
        referenced_ids
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offsets.
    /// This is needed to adjust stack pointers on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &ValueDomain,
    ) {
        let inner = Arc::make_mut(&mut self.inner);
        for elem in inner.memory.values_mut() {
            elem.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        inner.memory.clear_top_values();
        if inner.pointer_targets.get(old_id).is_some() {
            inner.pointer_targets.remove(old_id);
            inner.pointer_targets.insert(new_id.clone());
        }
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

    /// Remove the provided IDs from the target lists of all pointers in the memory object.
    /// Also remove them from the pointer_targets list.
    ///
    /// If this operation would produce an empty value, it replaces it with a `Top` value instead.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.pointer_targets = inner
            .pointer_targets
            .difference(ids_to_remove)
            .cloned()
            .collect();
        for value in inner.memory.values_mut() {
            value.remove_ids(ids_to_remove);
            if value.is_empty() {
                *value = value.top();
            }
        }
        inner.memory.clear_top_values(); // In case the previous operation left *Top* values in the memory struct.
    }

    /// Get the type of the memory object.
    pub fn get_object_type(&self) -> Option<ObjectType> {
        self.inner.type_
    }

    /// Marks all memory as `Top` and adds the `additional_targets` to the pointer targets.
    /// Represents the effect of unknown write instructions to the object
    /// which may include writing pointers to targets from the `additional_targets` set to the object.
    pub fn assume_arbitrary_writes(&mut self, additional_targets: &BTreeSet<AbstractIdentifier>) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.memory.mark_all_values_as_top();
        inner
            .pointer_targets
            .extend(additional_targets.iter().cloned());
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
mod tests {
    use super::*;

    fn new_abstract_object() -> AbstractObject {
        let inner = Inner {
            pointer_targets: BTreeSet::new(),
            is_unique: true,
            state: ObjectState::Alive,
            type_: Some(ObjectType::Heap),
            memory: MemRegion::new(ByteSize::new(8)),
            lower_index_bound: Bitvector::from_u64(0).into(),
            upper_index_bound: Bitvector::from_u64(99).into(),
        };
        inner.into()
    }

    fn new_data(number: i64) -> Data {
        bv(number).into()
    }

    fn bv(number: i64) -> ValueDomain {
        ValueDomain::from(Bitvector::from_i64(number))
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
            Data::new_top(ByteSize::new(8))
        );
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            new_data(3)
        );
        object.set_value(new_data(4), &bv(-12)).unwrap();
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            Data::new_top(ByteSize::new(8))
        );
        object.merge_value(new_data(23), &bv(-12));
        assert_eq!(
            object.get_value(Bitvector::from_i64(-12), ByteSize::new(8)),
            IntervalDomain::mock(4, 23).with_stride(19).into()
        );

        let mut other_object = new_abstract_object();
        object.set_value(new_data(0), &bv(0)).unwrap();
        other_object.set_value(new_data(0), &bv(0)).unwrap();
        let merged_object = object.merge(&other_object);
        assert_eq!(
            merged_object
                .get_value(Bitvector::from_i64(-12), ByteSize::new(8))
                .get_absolute_value(),
            Some(&IntervalDomain::mock(4, 23).with_stride(19).into())
        );
        assert!(merged_object
            .get_value(Bitvector::from_i64(-12), ByteSize::new(8))
            .contains_top());
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
        let pointer = DataDomain::mock_from_target_map(target_map.clone());
        object.set_value(pointer, &bv(-15)).unwrap();
        assert_eq!(object.get_referenced_ids_overapproximation().len(), 3);

        object.replace_abstract_id(
            &new_id("time_1", "RAX"),
            &new_id("time_234", "RAX"),
            &bv(10),
        );
        target_map.remove(&new_id("time_1", "RAX"));
        let modified_pointer = DataDomain::mock_from_target_map(target_map);
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            modified_pointer
        );

        object.replace_abstract_id(
            &new_id("time_1", "RBX"),
            &new_id("time_234", "RBX"),
            &bv(10),
        );
        let mut target_map = BTreeMap::new();
        target_map.insert(new_id("time_234", "RAX"), bv(30));
        target_map.insert(new_id("time_234", "RBX"), bv(50));
        let modified_pointer = DataDomain::mock_from_target_map(target_map);
        assert_eq!(
            object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
            modified_pointer
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
        let pointer = DataDomain::mock_from_target_map(target_map.clone());
        object.set_value(pointer, &bv(-15)).unwrap();
        assert_eq!(object.get_referenced_ids_overapproximation().len(), 3);

        let ids_to_remove = vec![new_id("time_1", "RAX"), new_id("time_23", "RBX")]
            .into_iter()
            .collect();
        object.remove_ids(&ids_to_remove);
        assert_eq!(
            object.get_referenced_ids_overapproximation(),
            &vec![new_id("time_234", "RAX"), new_id("time_1", "RBX")]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn access_contained_in_bounds() {
        let object = new_abstract_object();
        assert!(object.access_contained_in_bounds(&IntervalDomain::mock(0, 99), ByteSize::new(1)));
        assert!(!object.access_contained_in_bounds(&IntervalDomain::mock(-1, -1), ByteSize::new(8)));
        assert!(object.access_contained_in_bounds(&IntervalDomain::mock(92, 92), ByteSize::new(8)));
        assert!(!object.access_contained_in_bounds(&IntervalDomain::mock(93, 93), ByteSize::new(8)));
    }
}
