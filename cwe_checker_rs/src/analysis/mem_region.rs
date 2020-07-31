/*!
A memory region is an abstract domain representing a continuous region of memory.
For example, a stack domain containing values written to the stack can be represented with a memory region.

Design notes:
- The values do not need a fixed size.
Instead you need to provide the size of an element when adding it to the memory region.
- Whenever you try to read from an address that is not assigned to a value, the `Value::top()` element gets returned.
The reason behind this is that the value could be anything.
- Whenever adding an element intersects existing elements, the existing ones get removed from the memory region.
The reason is that reading the old positions afterwards could yield anything.
- Whenever a read from a correct position but with an incorrect size occurs, `Value::top()` gets returned.
That is because the value could be anything if the size read is too big and reading of partial values is not implemented for this type.
- An empty memory region could yield anything (in the sense of `Value::top`) at a read at any position.
In that regard, an empty memory region is actually the `top()` element of the domain.
- TODO: Implement the abstract domain trait for MemRegion.
- TODO: Remove the implicit saving of element sizes, as ValueDomains have now an intrinsic size.
Implementation needs is_top() to be a member function of the ValueDomain trait.
*/

use crate::abstract_domain::*;
use crate::bil::{BitSize, Bitvector};
use apint::{Int, Width};
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::DerefMut;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct Element<T> {
    size: i64,
    value: T,
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq, Deref)]
#[deref(forward)]
pub struct MemRegion<T: AbstractDomain + ValueDomain + std::fmt::Debug>(Arc<MemRegionData<T>>);

impl<T: AbstractDomain + ValueDomain + std::fmt::Debug> DerefMut for MemRegion<T> {
    fn deref_mut(&mut self) -> &mut MemRegionData<T> {
        Arc::make_mut(&mut self.0)
    }
}

// TODO: most of the functions in this impl block should be moved to MemRegionData (or removed, if they are only thin wrappers).
impl<T: AbstractDomain + ValueDomain + std::fmt::Debug> MemRegion<T> {
    pub fn new(address_bitsize: BitSize) -> Self {
        MemRegion(Arc::new(MemRegionData::new(address_bitsize)))
    }

    pub fn get_address_bitsize(&self) -> BitSize {
        self.0.get_address_bitsize()
    }

    pub fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            MemRegion(Arc::new(self.0.merge(&other.0)))
        }
    }

    pub fn add(&mut self, value: T, position: Bitvector) {
        Arc::make_mut(&mut self.0).add(value, position)
    }

    pub fn get(&self, position: Bitvector, size_in_bytes: u64) -> T {
        self.0.get(position, size_in_bytes)
    }

    pub fn remove(&mut self, position: Bitvector, size_in_bytes: Bitvector) {
        Arc::make_mut(&mut self.0).remove(position, size_in_bytes)
    }

    pub fn iter_values(&self) -> std::collections::btree_map::Values<'_, i64, T> {
        self.0.values.values()
    }

    pub fn iter_values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, i64, T> {
        Arc::make_mut(&mut self.0).values.values_mut()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<i64, T> {
        self.0.values.iter()
    }
}

/// An abstract domain representing a continuous region of memory. See the module level description for more.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct MemRegionData<T: AbstractDomain + ValueDomain + std::fmt::Debug> {
    address_bitsize: BitSize,
    values: BTreeMap<i64, T>,
}

impl<T: AbstractDomain + ValueDomain + std::fmt::Debug> MemRegionData<T> {
    /// create a new, empty MemRegion
    pub fn new(address_bitsize: BitSize) -> MemRegionData<T> {
        MemRegionData {
            address_bitsize,
            values: BTreeMap::new(),
        }
    }

    pub fn get_address_bitsize(&self) -> BitSize {
        self.address_bitsize
    }

    /// Remove all elements intersecting the provided interval.
    /// This function does not sanitize its inputs.
    fn clear_interval(&mut self, position: i64, size: i64) {
        // If the previous element intersects the range, remove it
        if let Some((prev_pos, prev_size)) = self
            .values
            .range(..position)
            .map(|(pos, elem)| (*pos, elem.bitsize() as i64 / 8))
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
        assert_eq!(position.width().to_usize(), self.address_bitsize as usize);
        let position = Int::from(position).try_to_i64().unwrap();
        assert!(value.bitsize() % 8 == 0);
        let size_in_bytes = value.bitsize() as i64 / 8;
        assert!(size_in_bytes > 0);

        self.clear_interval(position, size_in_bytes);
        if !value.is_top() {
            // top()-values do not need to be explicitly saved, as they don't contain any information anyway.
            self.values.insert(position, value);
        }
    }

    /// Get the value at the given position.
    /// If there is no value at the position or the size of the element is not the same as the provided size, return `T::top()`.
    pub fn get(&self, position: Bitvector, size_in_bytes: u64) -> T {
        assert_eq!(position.width().to_usize(), self.address_bitsize as usize);
        let position = Int::from(position).try_to_i64().unwrap();
        let size = size_in_bytes as i64;
        assert!(size > 0);

        if let Some(elem) = self.values.get(&position) {
            if (elem.bitsize() as i64) == (size * 8) {
                return elem.clone();
            }
        }
        let bitsize = 8 * size as u16;
        T::new_top(bitsize)
    }

    /// Remove all elements intersecting the provided interval.
    pub fn remove(&mut self, position: Bitvector, size_in_bytes: Bitvector) {
        assert_eq!(position.width().to_usize(), self.address_bitsize as usize);
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
        assert_eq!(self.address_bitsize, other.address_bitsize);

        let mut merged_values: BTreeMap<i64, T> = BTreeMap::new();

        // add all elements contained in both memory regions
        for (pos_left, elem_left) in self.values.iter() {
            if let Some((_pos_right, elem_right)) = other.values.get_key_value(pos_left) {
                if elem_left.bitsize() == elem_right.bitsize() {
                    let merged_val = elem_left.merge(&elem_right);
                    if !merged_val.is_top() {
                        // we discard top()-values, as they don't contain information
                        merged_values.insert(*pos_left, merged_val);
                    }
                }
            }
        }

        MemRegionData {
            address_bitsize: self.address_bitsize,
            values: merged_values,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, PartialOrd, Ord)]
    struct MockDomain(i64, BitSize);

    impl AbstractDomain for MockDomain {
        fn top(&self) -> MockDomain {
            MockDomain::new_top(self.1)
        }
    }

    impl ValueDomain for MockDomain {
        fn bitsize(&self) -> BitSize {
            self.1
        }

        fn new_top(bitsize: BitSize) -> MockDomain {
            MockDomain(0, bitsize)
        }

        fn bin_op(&self, _op: crate::bil::BinOpType, _rhs: &Self) -> Self {
            Self::new_top(self.1)
        }

        fn un_op(&self, _op: crate::bil::UnOpType) -> Self {
            Self::new_top(self.1)
        }

        fn cast(&self, _kind: crate::bil::CastType, width: BitSize) -> Self {
            Self::new_top(width)
        }
    }

    fn mock(val: i64, bitsize: BitSize) -> MockDomain {
        MockDomain(val, bitsize)
    }

    fn bv(val: i64) -> Bitvector {
        Bitvector::from_i64(val)
    }

    #[test]
    fn mem_region() {
        let mut region: MemRegion<MockDomain> = MemRegion::new(64);
        region.add(mock(5, 3 * 8), bv(5));
        assert_eq!(region.get(bv(5), 3), mock(5, 3 * 8));
        region.add(mock(7, 2 * 8), bv(8));
        assert_eq!(region.get(bv(8), 2), mock(7, 2 * 8));
        assert_eq!(region.get(bv(5), 3), mock(5, 3 * 8));
        assert_eq!(region.get(bv(5), 2), MockDomain::new_top(2 * 8));
        region.add(mock(9, 2 * 8), bv(6));
        assert_eq!(region.get(bv(6), 2), mock(9, 2 * 8));
        assert_eq!(region.get(bv(5), 3), MockDomain::new_top(3 * 8));
        assert_eq!(region.get(bv(8), 2), mock(7, 2 * 8));
        region.add(mock(9, 11 * 8), bv(-3));
        assert_eq!(region.get(bv(-3), 11), mock(9, 11 * 8));
        assert_eq!(region.get(bv(6), 2), MockDomain::new_top(2 * 8));
        assert_eq!(region.get(bv(8), 2), mock(7, 2 * 8));

        let mut other_region = MemRegion::new(64);
        other_region.add(mock(7, 2 * 8), bv(8));
        assert!(region != other_region);
        let merged_region = region.merge(&other_region);
        assert_eq!(merged_region.get(bv(8), 2), mock(7, 2 * 8));
        assert_eq!(merged_region.get(bv(-3), 11), MockDomain::new_top(11 * 8));
        other_region.add(mock(9, 11 * 8), bv(-3));
        assert_eq!(region, other_region);
    }

    #[test]
    fn do_not_save_top_elements() {
        let mut region: MemRegionData<MockDomain> = MemRegionData::new(64);
        region.add(MockDomain::new_top(4 * 8), bv(5));
        assert_eq!(region.values.len(), 0);

        let mut other_region: MemRegionData<MockDomain> = MemRegionData::new(64);
        region.add(mock(5, 4 * 8), bv(5));
        other_region.add(mock(7, 4 * 8), bv(5));
        let merged_region = region.merge(&other_region);
        assert_eq!(region.values.len(), 1);
        assert_eq!(other_region.values.len(), 1);
        assert_eq!(merged_region.values.len(), 0);
    }
}
