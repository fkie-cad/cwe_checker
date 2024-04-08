//! Tracking of taint in memory.

use crate::abstract_domain::{AbstractIdentifier, DomainMap, MapMergeStrategy, MemRegion};

use super::Taint;

use std::collections::BTreeMap;

/// Strategy for merging two memory taint states.
///
/// Essentially a [`UnionMergeStrategy`], i.e., the set of keys is the union of
/// the individual key sets, but we do not use the merging provided by the
/// [`MemRegion`] type on the intersection. Instead, we implement our own
/// merging of `MemRegion<Taint>` in [`merge_memory_object_with_offset`].
///
/// [`UnionMergeStrategy`]: crate::abstract_domain::UnionMergeStrategy
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemoryTaintMergeStrategy {
    _private: (), // Marker to prevent instantiation
}

impl MapMergeStrategy<AbstractIdentifier, MemRegion<Taint>> for MemoryTaintMergeStrategy {
    fn merge_map_with(
        memory_taint: &mut BTreeMap<AbstractIdentifier, MemRegion<Taint>>,
        other_memory_taint: &BTreeMap<AbstractIdentifier, MemRegion<Taint>>,
    ) {
        for (aid, other_memory_object) in other_memory_taint.iter() {
            memory_taint
                .entry(aid.clone())
                .and_modify(|memory_object| {
                    merge_memory_object_with_offset(memory_object, other_memory_object, 0);
                })
                .or_insert_with(|| other_memory_object.clone());
        }
    }
}

/// Represents our knowledge about taint in memory at a particular point in the
/// program.
pub type MemoryTaint = DomainMap<AbstractIdentifier, MemRegion<Taint>, MemoryTaintMergeStrategy>;

impl MemoryTaint {
    /// Merges the given pair of abstract identifier and memory object into the
    /// state.
    pub fn merge_memory_object_with_offset(
        &mut self,
        aid: &AbstractIdentifier,
        other_memory_object: &MemRegion<Taint>,
        offset: i64,
    ) {
        use std::collections::btree_map::Entry::*;

        match self.entry(aid.clone()) {
            Occupied(mut current_memory_object) => {
                let current_memory_object = current_memory_object.get_mut();

                merge_memory_object_with_offset(current_memory_object, other_memory_object, offset);
            }
            Vacant(entry) => {
                let mut new_memory_object = other_memory_object.clone();

                new_memory_object.add_offset_to_all_indices(offset);
                entry.insert(new_memory_object);
            }
        }
    }
}

// FIXME: The used algorithm for merging the taints contained in memory
// regions is unsound when merging taints that intersect only partially.
// If, for example, in state A `RSP[0:3]` is tainted and in state B
// `RSP[2:3]` is tainted, A u B will only report `RSP[2:3]` as tainted.
//
// For the NULL pointer dereference check, however, this should not have an
// effect in practice, since these values are usually unsound or a sign of
// incorrect behavior of the analysed program.
// FIXME: This looks a lot like it should be a method on `MemRegion<T>`.
/// Merges `other_memory_object` into `memory_object`.
///
/// The `other_memory_object` is shifted by `offset` before the merging is
/// performed. For partially overlapping taints, the value of
/// `other_memory_object` always "wins", i.e., it ends up in the merged object
/// and the overlapped value in `memory_object` is discarded.
fn merge_memory_object_with_offset(
    memory_object: &mut MemRegion<Taint>,
    other_memory_object: &MemRegion<Taint>,
    offset: i64,
) {
    for (index, taint) in other_memory_object.iter() {
        // WARNING: This is not using the `merge` function of `Taint`. It
        // will become even more incorrect once we have more complicated taint.
        memory_object.insert_at_byte_index(*taint, *index + offset);
        // FIXME: Unsound in theory for partially intersecting
        // taints. Should not matter in practice.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    // FIXME: This illustrates the current, unsound merging of memory taints. Make
    // sure to change this test when you work on a better memory model.
    #[test]
    fn merge_memory_object_overlapping() {
        let taint_8 = Taint::Tainted(ByteSize::new(8));
        let taint_4 = Taint::Tainted(ByteSize::new(4));

        let mut memory_object = MemRegion::<Taint>::new(ByteSize::new(8));
        let mut other_memory_object = MemRegion::<Taint>::new(ByteSize::new(8));

        memory_object.insert_at_byte_index(taint_4, 2);
        memory_object.insert_at_byte_index(taint_8, 8);
        memory_object.insert_at_byte_index(taint_4, 16);
        other_memory_object.insert_at_byte_index(taint_8, 0);
        other_memory_object.insert_at_byte_index(taint_4, 8);
        other_memory_object.insert_at_byte_index(taint_4, 14);

        merge_memory_object_with_offset(&mut memory_object, &other_memory_object, 0);

        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(0)),
            Some(taint_8)
        );
        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(2)), None);
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(8)),
            Some(taint_4)
        );
        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(12)), None);
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(14)),
            Some(taint_4)
        );
        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(16)), None);
    }

    #[test]
    fn merge_memory_object_nonoverlapping() {
        let taint_8 = Taint::Tainted(ByteSize::new(8));
        let taint_4 = Taint::Tainted(ByteSize::new(4));
        let untaint_4 = Taint::Top(ByteSize::new(4));

        let mut memory_object = MemRegion::<Taint>::new(ByteSize::new(8));
        let mut other_memory_object = MemRegion::<Taint>::new(ByteSize::new(8));

        memory_object.insert_at_byte_index(taint_8, 8);
        other_memory_object.insert_at_byte_index(untaint_4, 0);
        other_memory_object.insert_at_byte_index(taint_4, 4);
        other_memory_object.insert_at_byte_index(untaint_4, 8);

        merge_memory_object_with_offset(&mut memory_object, &other_memory_object, 0);

        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(0)), None);
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(4)),
            Some(taint_4)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(8)),
            Some(taint_8)
        );
    }

    #[test]
    fn merge_memory_object_with_offset_nonoverlapping() {
        let taint_8 = Taint::Tainted(ByteSize::new(8));
        let taint_4 = Taint::Tainted(ByteSize::new(4));

        let mut memory_object = MemRegion::<Taint>::new(ByteSize::new(8));
        let mut other_memory_object = MemRegion::<Taint>::new(ByteSize::new(8));

        memory_object.insert_at_byte_index(taint_8, 8);
        other_memory_object.insert_at_byte_index(taint_4, 8);
        other_memory_object.insert_at_byte_index(taint_4, 12);

        merge_memory_object_with_offset(&mut memory_object, &other_memory_object, 8);

        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(0)), None);
        assert_eq!(memory_object.get_unsized(Bitvector::from_i64(4)), None);
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(8)),
            Some(taint_8)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(16)),
            Some(taint_4)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(20)),
            Some(taint_4)
        );

        merge_memory_object_with_offset(&mut memory_object, &other_memory_object, -8);

        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(0)),
            Some(taint_4)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(4)),
            Some(taint_4)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(8)),
            Some(taint_8)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(16)),
            Some(taint_4)
        );
        assert_eq!(
            memory_object.get_unsized(Bitvector::from_i64(20)),
            Some(taint_4)
        );
    }
}
