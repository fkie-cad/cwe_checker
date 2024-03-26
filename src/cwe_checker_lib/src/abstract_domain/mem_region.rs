use super::{AbstractDomain, HasTop, SizedDomain};
use crate::intermediate_representation::ByteSize;
use crate::prelude::*;
use crate::utils::debug::ToJsonCompact;
use apint::{Int, Width};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A memory region is an abstract domain representing a continuous region of memory, e.g. the stack frame of a function.
///
/// This implementation can only save values of one abstract domain type,
/// which must implement the `HasByteSize` and `HasTop` domains,
/// and it can only track values with a known offset, i.e. it cannot handle arrays of any kind.
/// Offsets are internally saved as signed integers, which allows negative offsets,
/// e.g. for downward growing stack frames.
///
/// An empty memory region means that nothing is known about the values at any offset inside the region.
/// Thus an empty memory region actually represents the *Top* element of its abstract domain.
///
/// To allow cheap cloning of a `MemRegion`, the actual data is wrapped inside an `Arc`.
#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct MemRegion<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> {
    inner: Arc<Inner<T>>,
}

/// The internal data of a memory region. See the description of `MemRegion` for more.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct Inner<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> {
    address_bytesize: ByteSize,
    values: BTreeMap<i64, T>,
}

#[allow(clippy::from_over_into)]
impl<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> std::convert::Into<MemRegion<T>>
    for Inner<T>
{
    /// Wrap the contents of a `MemRegion` into an `Arc<..>`.
    fn into(self) -> MemRegion<T> {
        MemRegion {
            inner: Arc::new(self),
        }
    }
}

impl<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> AbstractDomain for MemRegion<T> {
    /// Short-circuting the `MemRegionData::merge` function if `self==other`,
    /// to prevent unneccessary cloning.
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            self.merge_inner(other)
        }
    }

    /// The *Top* element is represented by an empty memory region.
    fn is_top(&self) -> bool {
        self.inner.values.is_empty()
    }
}

impl<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> HasTop for MemRegion<T> {
    /// Return a new, empty memory region with the same address bytesize as `self`, representing the *Top* element of the abstract domain.
    fn top(&self) -> Self {
        Self::new(self.get_address_bytesize())
    }
}

impl<T> ToJsonCompact for MemRegion<T>
where
    T: ToJsonCompact + AbstractDomain + SizedDomain + HasTop + std::fmt::Debug,
{
    fn to_json_compact(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.iter()
                .map(|(offset, val)| (offset.to_string(), val.to_json_compact()))
                .collect(),
        )
    }
}

impl<T: AbstractDomain + SizedDomain + HasTop + std::fmt::Debug> MemRegion<T> {
    /// Create a new, empty memory region.
    pub fn new(address_bytesize: ByteSize) -> MemRegion<T> {
        Inner {
            address_bytesize,
            values: BTreeMap::new(),
        }
        .into()
    }

    /// Get the bytesize of pointers for the address space that the memory region belongs to.
    pub fn get_address_bytesize(&self) -> ByteSize {
        self.inner.address_bytesize
    }

    /// Remove all elements intersecting the provided interval.
    /// This function does not sanitize its inputs.
    fn clear_interval(&mut self, position: i64, size: i64) {
        let inner = Arc::make_mut(&mut self.inner);
        // If the previous element intersects the range, remove it
        if let Some((prev_pos, prev_size)) = inner
            .values
            .range(..position)
            .map(|(pos, elem)| (*pos, u64::from(elem.bytesize()) as i64))
            .last()
        {
            if prev_pos + prev_size > position {
                inner.values.remove(&prev_pos);
            }
        }
        // remove all other intersecting elements
        let intersecting_elements: Vec<i64> = inner
            .values
            .range(position..(position + size))
            .map(|(pos, _elem)| *pos)
            .collect();
        for index in intersecting_elements {
            inner.values.remove(&index);
        }
    }

    /// Add a value to the memory region.
    pub fn add(&mut self, value: T, position: Bitvector) {
        assert_eq!(
            ByteSize::from(position.width()),
            self.inner.address_bytesize
        );
        let position = Int::from(position).try_to_i64().unwrap();
        self.insert_at_byte_index(value, position);
    }

    /// Insert a value into the memory region at the given position.
    /// The position is the index (in bytes) in the memory region.
    pub fn insert_at_byte_index(&mut self, value: T, position: i64) {
        let size_in_bytes = u64::from(value.bytesize()) as i64;
        assert!(size_in_bytes > 0);

        self.clear_interval(position, size_in_bytes);
        if !value.is_top() {
            // top()-values do not need to be explicitly saved, as they don't contain any information anyway.
            Arc::make_mut(&mut self.inner)
                .values
                .insert(position, value);
        }
    }

    /// Get the value at the given position.
    /// If there is no value at the position or the size of the element is not the same as the provided size, return `T::new_top()`.
    pub fn get(&self, position: Bitvector, size_in_bytes: ByteSize) -> T {
        assert_eq!(
            ByteSize::from(position.width()),
            self.inner.address_bytesize
        );
        let position = Int::from(position).try_to_i64().unwrap();

        if let Some(elem) = self.inner.values.get(&position) {
            if elem.bytesize() == size_in_bytes {
                return elem.clone();
            }
        }
        T::new_top(size_in_bytes)
    }

    /// Get the value at the given position regardless of the value size.
    /// Return `None` if there is no value at that position in the memory region.
    pub fn get_unsized(&self, position: Bitvector) -> Option<T> {
        assert_eq!(
            ByteSize::from(position.width()),
            self.inner.address_bytesize
        );
        let position = Int::from(position).try_to_i64().unwrap();

        self.inner.values.get(&position).cloned()
    }

    /// Remove all elements intersecting the provided interval.
    pub fn remove(&mut self, position: Bitvector, size_in_bytes: Bitvector) {
        assert_eq!(
            ByteSize::from(position.width()),
            self.inner.address_bytesize
        );
        let position = Int::from(position).try_to_i64().unwrap();
        let size = Int::from(size_in_bytes).try_to_i64().unwrap();
        assert!(size > 0);

        self.clear_interval(position, size);
    }

    /// If the `MemRegion` contains an element at the given position and with the given size
    /// then merge it with a `Top` element.
    /// Else clear all values intersecting the range from `position` to `position + size`.
    pub fn merge_write_top(&mut self, position: Bitvector, size: ByteSize) {
        let position = Int::from(position).try_to_i64().unwrap();
        if let Some(prev_value) = self.inner.values.get(&position) {
            if prev_value.bytesize() == size {
                let merged_value = prev_value.merge(&prev_value.top());
                let inner = Arc::make_mut(&mut self.inner);
                if merged_value.is_top() {
                    inner.values.remove(&position);
                } else {
                    inner.values.insert(position, merged_value);
                }
                return;
            }
        }
        self.clear_interval(position, u64::from(size) as i64)
    }

    /// Emulate a write operation of a value to an unknown offset in the range between `start` and `end`
    /// by merging all values in the range with `Top` (as we don't exactly know which values are overwritten).
    pub fn mark_interval_values_as_top(&mut self, start: i64, end: i64, elem_size: ByteSize) {
        self.merge_values_intersecting_range_with_top(start, end + u64::from(elem_size) as i64)
    }

    /// Merge all values intersecting the given range with `Top`.
    /// If `Top` is a maximal element of the value abstract domain,
    /// this effectively removes all values intersecting the range.
    fn merge_values_intersecting_range_with_top(&mut self, start: i64, end: i64) {
        let inner = Arc::make_mut(&mut self.inner);
        // If the previous element intersects the range, merge it with Top
        if let Some((prev_pos, prev_size)) = inner
            .values
            .range(..start)
            .map(|(pos, elem)| (*pos, u64::from(elem.bytesize()) as i64))
            .last()
        {
            if prev_pos + prev_size > start {
                let value = inner.values.get(&prev_pos).unwrap();
                let merged_value = value.merge(&value.top());
                if merged_value.is_top() {
                    inner.values.remove(&prev_pos);
                } else {
                    inner.values.insert(prev_pos, merged_value);
                }
            }
        }
        // Merge all other intersecting elements with Top
        let intersecting_elements: Vec<_> = inner
            .values
            .range(start..end)
            .map(|(pos, elem)| (*pos, elem.merge(&elem.top())))
            .collect();
        for (index, merged_value) in intersecting_elements {
            if merged_value.is_top() {
                inner.values.remove(&index);
            } else {
                inner.values.insert(index, merged_value);
            }
        }
    }

    /// Emulate a write operation to an unknown offset by merging all values with `Top`
    /// to indicate that they may have been overwritten
    pub fn mark_all_values_as_top(&mut self) {
        let inner = Arc::make_mut(&mut self.inner);
        for value in inner.values.values_mut() {
            *value = value.merge(&value.top());
        }
        self.clear_top_values();
    }

    /// Add the given offset to the indices of all values contained in the memory region.
    pub fn add_offset_to_all_indices(&mut self, offset: i64) {
        if offset == 0 {
            return;
        }
        let mut new_values = BTreeMap::new();
        for (index, value) in self.inner.values.iter() {
            new_values.insert(*index + offset, value.clone());
        }
        let inner = Arc::make_mut(&mut self.inner);
        inner.values = new_values;
    }

    /// Merge two memory regions.
    ///
    /// Values at the same position and with the same size get merged via their merge function.
    /// Values intersecting other values but with not exactly matching position or size are not added to the merged region.
    /// Values that do not intersect a value from the other `MemRegion`
    /// are merged with `Top` before adding them.
    /// This can only add elements to the merged domain if the `Top` value is not a maximal element of the abstract domain.
    fn merge_inner(&self, other: &MemRegion<T>) -> MemRegion<T> {
        assert_eq!(self.inner.address_bytesize, other.inner.address_bytesize);

        let mut zipped: BTreeMap<i64, (Option<&T>, Option<&T>)> = BTreeMap::new();
        for (index, elem) in self.inner.values.iter() {
            if let Some(other_elem) = other.inner.values.get(index) {
                zipped.insert(*index, (Some(elem), Some(other_elem)));
            } else {
                zipped.insert(*index, (Some(elem), None));
            }
        }
        for (index, other_elem) in other.inner.values.iter() {
            if self.inner.values.get(index).is_none() {
                zipped.insert(*index, (None, Some(other_elem)));
            }
        }

        let mut merged_values: BTreeMap<i64, T> = BTreeMap::new();
        let mut merged_range_end = i64::MIN;
        for (index, (left, right)) in zipped.iter() {
            let elem_range_end = compute_range_end(*index, *left, *right);
            if *index >= merged_range_end {
                // The element does not overlap a previous element
                if let Some((next_index, _)) = zipped.range((index + 1)..).next() {
                    if *next_index >= elem_range_end {
                        // The element does not overlap a subsequent element
                        if let Some(merged) = merge_or_merge_with_top(*left, *right) {
                            merged_values.insert(*index, merged);
                        }
                    }
                } else if let Some(merged) = merge_or_merge_with_top(*left, *right) {
                    merged_values.insert(*index, merged);
                }
            }
            merged_range_end = std::cmp::max(merged_range_end, elem_range_end);
        }

        Inner {
            address_bytesize: self.inner.address_bytesize,
            values: merged_values,
        }
        .into()
    }

    /// Get an iterator over all elements together with their offset into the memory region.
    pub fn iter(&self) -> std::collections::btree_map::Iter<i64, T> {
        self.inner.values.iter()
    }

    /// Get an iterator over all values in the memory region
    pub fn values(&self) -> std::collections::btree_map::Values<i64, T> {
        self.inner.values.values()
    }

    /// Get the map of all elements including their offset into the memory region.
    pub fn entry_map(&self) -> &BTreeMap<i64, T> {
        &self.inner.values
    }

    /// Get an iterator over all values in the memory region for in-place manipulation.
    /// Note that one can changes values to *Top* using the iterator.
    /// These values should be removed from the memory region using `clear_top_values()`.
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<i64, T> {
        Arc::make_mut(&mut self.inner).values.values_mut()
    }

    /// Remove all values representing the *Top* element from the internal value store,
    /// as these should not be saved in the internal representation.
    pub fn clear_top_values(&mut self) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.values.retain(|_key, value| !value.is_top());
    }
}

/// Helper function that either merges `left` and `right`
/// or, if one of them is `None`, merges the other with a `Top` value.
/// Furthermore, if `left` and `right` have different byte sizes
/// or the merge operation returns a `Top` value, then `None` is returned.
/// Panics if both `left` and `right` are `None`.
fn merge_or_merge_with_top<T: AbstractDomain + SizedDomain>(
    left: Option<&T>,
    right: Option<&T>,
) -> Option<T> {
    match (left, right) {
        (Some(elem_left), Some(elem_right)) => {
            if elem_left.bytesize() == elem_right.bytesize() {
                let merged = elem_left.merge(elem_right);
                if !merged.is_top() {
                    return Some(merged);
                }
            }
            None
        }
        (Some(elem), None) | (None, Some(elem)) => {
            let merged = elem.merge(&T::new_top(elem.bytesize()));
            if !merged.is_top() {
                Some(merged)
            } else {
                None
            }
        }
        (None, None) => panic!(),
    }
}

/// Helper function computing `index` plus the maximum of the bytesizes of `left` and `right`.
/// Panics if both `left` and `right` are `None`.
fn compute_range_end<T: SizedDomain>(index: i64, left: Option<&T>, right: Option<&T>) -> i64 {
    match (left, right) {
        (Some(left_elem), Some(right_elem)) => {
            let left_size = u64::from(left_elem.bytesize()) as i64;
            let right_size = u64::from(right_elem.bytesize()) as i64;
            index + std::cmp::max(left_size, right_size)
        }
        (Some(elem), None) | (None, Some(elem)) => index + u64::from(elem.bytesize()) as i64,
        (None, None) => panic!(),
    }
}

#[cfg(test)]
mod tests;
