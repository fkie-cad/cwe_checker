//! Methods of [`AbstractObjectList`] that manage memory access rules
//! or check whether they are violated.
//! E.g. checks for use-after-free or buffer overflow checks.

use super::*;

impl AbstractObjectList {
    /// Check whether a memory access at the given address (and accessing `size` many bytes)
    /// may be an out-of-bounds memory access.
    ///
    /// Note that `Top` values as addresses are not marked as out-of-bounds,
    /// since they are more likely due to analysis imprecision than to actual out-of-bounds access.
    pub fn is_out_of_bounds_mem_access(
        &self,
        address: &Data,
        size: ByteSize,
        global_data: &RuntimeMemoryImage,
    ) -> bool {
        if let Some(value) = address.get_absolute_value() {
            if let Ok((start, end)) = value.try_to_offset_interval() {
                if start < 0 || end < start {
                    return true;
                }
                if global_data
                    .is_interval_readable(start as u64, end as u64 + u64::from(size) - 1)
                    .is_err()
                {
                    return true;
                }
            }
        }
        for (id, offset) in address.get_relative_values() {
            if let Some(object) = self.objects.get(id) {
                if !object.access_contained_in_bounds(offset, size) {
                    return true;
                }
            }
        }
        false
    }

    /// Set the lower index bound for indices to be considered inside the memory object.
    /// The bound is inclusive, i.e. the bound index itself is also considered to be inside the memory object.
    ///
    /// Any `bound` value other than a constant bitvector is interpreted as the memory object not having a lower bound.
    pub fn set_lower_index_bound(&mut self, object_id: &AbstractIdentifier, bound: &ValueDomain) {
        let object = self.objects.get_mut(object_id).unwrap();
        let bound = bound
            .clone()
            .try_to_bitvec()
            .map(|bitvec| bitvec.into())
            .unwrap_or_else(|_| BitvectorDomain::new_top(bound.bytesize()));
        object.set_lower_index_bound(bound);
    }

    /// Set the upper index bound for indices to be considered inside the memory object.
    /// The bound is inclusive, i.e. the bound index itself is also considered to be inside the memory object.
    ///
    /// Any `bound` value other than a constant bitvector is interpreted as the memory object not having an upper bound.
    pub fn set_upper_index_bound(&mut self, object_id: &AbstractIdentifier, bound: &ValueDomain) {
        let object = self.objects.get_mut(object_id).unwrap();
        let bound = bound
            .clone()
            .try_to_bitvec()
            .map(|bitvec| bitvec.into())
            .unwrap_or_else(|_| BitvectorDomain::new_top(bound.bytesize()));
        object.set_upper_index_bound(bound);
    }
}
