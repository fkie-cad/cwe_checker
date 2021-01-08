use super::{AbstractDomain, HasByteSize, HasTop};
use crate::bil::Bitvector;
use crate::intermediate_representation::ByteSize;
use apint::{Int, Width};
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::DerefMut;
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
#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq, Deref)]
#[deref(forward)]
pub struct MemRegion<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug>(
    Arc<MemRegionData<T>>,
);

impl<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> DerefMut for MemRegion<T> {
    fn deref_mut(&mut self) -> &mut MemRegionData<T> {
        Arc::make_mut(&mut self.0)
    }
}

impl<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> AbstractDomain for MemRegion<T> {
    /// Short-circuting the `MemRegionData::merge` function if `self==other`,
    /// to prevent unneccessary cloning.
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            MemRegion(Arc::new(self.0.merge(&other.0)))
        }
    }

    /// The *Top* element is represented by an empty memory region.
    fn is_top(&self) -> bool {
        self.values.is_empty()
    }
}

impl<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> HasTop for MemRegion<T> {
    /// Return a new, empty memory region with the same address bytesize as `self`, representing the *Top* element of the abstract domain.
    fn top(&self) -> Self {
        Self::new(self.get_address_bytesize())
    }
}

impl<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> MemRegion<T> {
    // Create a new, empty memory region.
    pub fn new(address_bytesize: ByteSize) -> Self {
        MemRegion(Arc::new(MemRegionData::new(address_bytesize)))
    }
}

/// The internal data of a memory region. See the description of `MemRegion` for more.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct MemRegionData<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> {
    address_bytesize: ByteSize,
    values: BTreeMap<i64, T>,
}

impl<T: AbstractDomain + HasByteSize + HasTop + std::fmt::Debug> MemRegionData<T> {
    /// create a new, empty MemRegion
    pub fn new(address_bytesize: ByteSize) -> MemRegionData<T> {
        MemRegionData {
            address_bytesize,
            values: BTreeMap::new(),
        }
    }

    /// Get the bitsize of pointers for the address space that the memory region belongs to.
    pub fn get_address_bytesize(&self) -> ByteSize {
        self.address_bytesize
    }

    /// Remove all elements intersecting the provided interval.
    /// This function does not sanitize its inputs.
    fn clear_interval(&mut self, position: i64, size: i64) {
        // If the previous element intersects the range, remove it
        if let Some((prev_pos, prev_size)) = self
            .values
            .range(..position)
            .map(|(pos, elem)| (*pos, u64::from(elem.bytesize()) as i64))
            .last()
        {
            if prev_pos + prev_size > position {
                self.values.remove(&prev_pos);
            }
        }
        // remove all other intersecting elements
        let intersecting_elements: Vec<i64> = self
            .values
            .range(position..(position + size))
            .map(|(pos, _elem)| *pos)
            .collect();
        for index in intersecting_elements {
            self.values.remove(&index);
        }
    }

    /// Add a value to the memory region.
    pub fn add(&mut self, value: T, position: Bitvector) {
        assert_eq!(ByteSize::from(position.width()), self.address_bytesize);
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
            self.values.insert(position, value);
        }
    }

    /// Get the value at the given position.
    /// If there is no value at the position or the size of the element is not the same as the provided size, return `T::new_top()`.
    pub fn get(&self, position: Bitvector, size_in_bytes: ByteSize) -> T {
        assert_eq!(ByteSize::from(position.width()), self.address_bytesize);
        let position = Int::from(position).try_to_i64().unwrap();

        if let Some(elem) = self.values.get(&position) {
            if elem.bytesize() == size_in_bytes {
                return elem.clone();
            }
        }
        T::new_top(size_in_bytes)
    }

    /// Get the value at the given position regardless of the value size.
    /// Return `None` if there is no value at that position in the memory region.
    pub fn get_unsized(&self, position: Bitvector) -> Option<T> {
        assert_eq!(ByteSize::from(position.width()), self.address_bytesize);
        let position = Int::from(position).try_to_i64().unwrap();

        self.values.get(&position).cloned()
    }

    /// Remove all elements intersecting the provided interval.
    pub fn remove(&mut self, position: Bitvector, size_in_bytes: Bitvector) {
        assert_eq!(ByteSize::from(position.width()), self.address_bytesize);
        let position = Int::from(position).try_to_i64().unwrap();
        let size = Int::from(size_in_bytes).try_to_i64().unwrap();
        assert!(size > 0);

        self.clear_interval(position, size);
    }

    /// Merge two memory regions.
    ///
    /// Values at the same position and with the same size get merged via their merge function.
    /// Other values are *not* added to the merged region, because they could be anything in at least one of the two regions.
    pub fn merge(&self, other: &MemRegionData<T>) -> MemRegionData<T> {
        assert_eq!(self.address_bytesize, other.address_bytesize);

        let mut merged_values: BTreeMap<i64, T> = BTreeMap::new();

        // add all elements contained in both memory regions
        for (pos_left, elem_left) in self.values.iter() {
            if let Some((_pos_right, elem_right)) = other.values.get_key_value(pos_left) {
                if elem_left.bytesize() == elem_right.bytesize() {
                    let merged_val = elem_left.merge(&elem_right);
                    if !merged_val.is_top() {
                        // we discard top()-values, as they don't contain information
                        merged_values.insert(*pos_left, merged_val);
                    }
                }
            }
        }

        MemRegionData {
            address_bytesize: self.address_bytesize,
            values: merged_values,
        }
    }

    /// Get an iterator over all elements together with their offset into the memory region.
    pub fn iter(&self) -> std::collections::btree_map::Iter<i64, T> {
        self.values.iter()
    }

    /// Get an iterator over all values in the memory region
    pub fn values(&self) -> std::collections::btree_map::Values<i64, T> {
        self.values.values()
    }

    /// Get an iterator over all values in the memory region for in-place manipulation.
    /// Note that one can changes values to *Top* using the iterator.
    /// These values should be removed from the memory region using `clear_top_values()`.
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<i64, T> {
        self.values.values_mut()
    }

    /// Remove all values representing the *Top* element from the internal value store,
    /// as these should not be saved in the internal representation.
    pub fn clear_top_values(&mut self) {
        let indices_to_remove: Vec<i64> = self
            .values
            .iter()
            .filter_map(
                |(index, value)| {
                    if value.is_top() {
                        Some(*index)
                    } else {
                        None
                    }
                },
            )
            .collect();
        for index in indices_to_remove {
            self.values.remove(&index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abstract_domain::RegisterDomain;
    use crate::bil::Bitvector;
    use crate::intermediate_representation::*;

    #[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, PartialOrd, Ord)]
    struct MockDomain(i64, ByteSize);

    impl AbstractDomain for MockDomain {
        fn merge(&self, other: &Self) -> Self {
            assert_eq!(self.1, other.1);
            if self == other {
                self.clone()
            } else {
                self.top()
            }
        }

        fn is_top(&self) -> bool {
            self == &self.top()
        }
    }

    impl HasByteSize for MockDomain {
        fn bytesize(&self) -> ByteSize {
            self.1
        }

        fn new_top(bytesize: ByteSize) -> MockDomain {
            MockDomain(0, bytesize)
        }
    }

    impl HasTop for MockDomain {
        fn top(&self) -> Self {
            Self::new_top(self.1)
        }
    }

    impl RegisterDomain for MockDomain {
        fn bin_op(&self, _op: BinOpType, _rhs: &Self) -> Self {
            Self::new_top(self.1)
        }

        fn un_op(&self, _op: UnOpType) -> Self {
            Self::new_top(self.1)
        }

        fn cast(&self, _kind: CastOpType, width: ByteSize) -> Self {
            Self::new_top(width)
        }

        fn subpiece(&self, _low_byte: ByteSize, size: ByteSize) -> Self {
            Self::new_top(size)
        }
    }

    fn mock(val: i64, bytesize: impl Into<ByteSize>) -> MockDomain {
        MockDomain(val, bytesize.into())
    }

    fn bv(val: i64) -> Bitvector {
        Bitvector::from_i64(val)
    }

    #[test]
    fn mem_region() {
        let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
        region.add(mock(5, 3u64), bv(5));
        assert_eq!(region.get(bv(5), ByteSize::from(3u64)), mock(5, 3u64));
        region.add(mock(7, 2u64), bv(8));
        assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));
        assert_eq!(region.get(bv(5), ByteSize::from(3u64)), mock(5, 3u64));
        assert_eq!(
            region.get(bv(5), ByteSize::from(2u64)),
            MockDomain::new_top(ByteSize::new(2))
        );
        region.add(mock(9, 2u64), bv(6));
        assert_eq!(region.get(bv(6), ByteSize::from(2u64)), mock(9, 2u64));
        assert_eq!(
            region.get(bv(5), ByteSize::from(3u64)),
            MockDomain::new_top(ByteSize::new(3))
        );
        assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));
        region.add(mock(9, 11u64), bv(-3));
        assert_eq!(region.get(bv(-3), ByteSize::from(11u64)), mock(9, 11u64));
        assert_eq!(
            region.get(bv(6), ByteSize::from(2u64)),
            MockDomain::new_top(ByteSize::new(2))
        );
        assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));

        let mut other_region = MemRegion::new(ByteSize::from(8u64));
        other_region.add(mock(7, 2u64), bv(8));
        assert!(region != other_region);
        let merged_region = region.merge(&other_region);
        assert_eq!(
            merged_region.get(bv(8), ByteSize::from(2u64)),
            mock(7, 2u64)
        );
        assert_eq!(
            merged_region.get(bv(-3), ByteSize::from(11u64)),
            MockDomain::new_top(ByteSize::from(11u64))
        );
        other_region.add(mock(9, 11u64), bv(-3));
        assert_eq!(region, other_region);
    }

    #[test]
    fn do_not_save_top_elements() {
        let mut region: MemRegionData<MockDomain> = MemRegionData::new(ByteSize::from(8u64));
        region.add(MockDomain::new_top(ByteSize::from(4u64)), bv(5));
        assert_eq!(region.values.len(), 0);

        let mut other_region: MemRegionData<MockDomain> = MemRegionData::new(ByteSize::from(8u64));
        region.add(mock(5, 4u64), bv(5));
        other_region.add(mock(7, 4u64), bv(5));
        let merged_region = region.merge(&other_region);
        assert_eq!(region.values.len(), 1);
        assert_eq!(other_region.values.len(), 1);
        assert_eq!(merged_region.values.len(), 0);
    }

    #[test]
    fn value_removals() {
        let mut region: MemRegionData<MockDomain> = MemRegionData::new(ByteSize::from(8u64));
        region.add(mock(1, 8u64), bv(0));
        region.add(mock(2, 8u64), bv(8));
        region.add(mock(3, 8u64), bv(16));
        region.add(mock(4, 8u64), bv(24));
        region.add(mock(5, 8u64), bv(32));

        assert_eq!(region.values.len(), 5);
        region.remove(bv(2), bv(3));
        assert_eq!(region.values.len(), 4);
        region.remove(bv(7), bv(1));
        assert_eq!(region.values.len(), 4);
        region.remove(bv(7), bv(2));
        assert_eq!(region.values.len(), 3);

        region.clear_interval(15, 1);
        assert_eq!(region.values.len(), 3);
        region.clear_interval(15, 3);
        assert_eq!(region.values.len(), 2);

        for val in region.values_mut() {
            if *val == mock(5, 8u64) {
                *val = mock(0, 8u64); // This is a *Top* element
            }
        }
        region.clear_top_values();
        assert_eq!(region.values.len(), 1);
        assert_eq!(region.get(bv(24), ByteSize::from(8u64)), mock(4, 8u64));
    }
}
