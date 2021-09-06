//! Methods of [`AbstractObjectList`] that manage memory access rules
//! or check whether they are violated.
//! E.g. checks for use-after-free or buffer overflow checks.

use super::*;

impl AbstractObjectList {
    /// Check the state of a memory object at a given address.
    /// Returns `true` if at least one of the targets of the pointer is dangling.
    /// If `report_unknown_states` is `true`,
    /// then objects with unknown states get reported if they are unique.
    /// I.e. objects representing more than one actual object (e.g. an array of object) will not get reported,
    /// even if their state is unknown and `report_unknown_states` is `true`.
    pub fn is_dangling_pointer(&self, address: &Data, report_unknown_states: bool) -> bool {
        for id in address.referenced_ids() {
            if let Some((object, _offset_id)) = self.objects.get(id) {
                match (report_unknown_states, object.get_state()) {
                    (_, ObjectState::Dangling) => return true,
                    (true, ObjectState::Unknown) => {
                        if object.is_unique() {
                            return true;
                        }
                    }
                    _ => (),
                }
            }
        }
        // No dangling pointer found
        false
    }

    /// Mark all memory objects targeted by the given `address` pointer,
    /// whose state is either dangling or unknown,
    /// as flagged.
    pub fn mark_dangling_pointer_targets_as_flagged(&mut self, address: &Data) {
        for id in address.referenced_ids() {
            let (object, _) = self.objects.get_mut(id).unwrap();
            if matches!(
                object.get_state(),
                ObjectState::Unknown | ObjectState::Dangling
            ) {
                object.set_state(ObjectState::Flagged);
            }
        }
    }

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
            if let Some((object, base_offset)) = self.objects.get(id) {
                let adjusted_offset = offset.clone() + base_offset.clone();
                if !adjusted_offset.is_top()
                    && !object.access_contained_in_bounds(&adjusted_offset, size)
                {
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
        let (object, base_offset) = self.objects.get_mut(object_id).unwrap();
        let bound = (bound.clone() + base_offset.clone())
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
        let (object, base_offset) = self.objects.get_mut(object_id).unwrap();
        let bound = (bound.clone() + base_offset.clone())
            .try_to_bitvec()
            .map(|bitvec| bitvec.into())
            .unwrap_or_else(|_| BitvectorDomain::new_top(bound.bytesize()));
        object.set_upper_index_bound(bound);
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    ///
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    /// Returns either a non-empty list of detected errors (like possible double frees) or `OK(())` if no errors were found.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &Data,
    ) -> Result<(), Vec<(AbstractIdentifier, Error)>> {
        let ids: Vec<AbstractIdentifier> = object_pointer.referenced_ids().cloned().collect();
        let mut possible_double_free_ids = Vec::new();
        if ids.len() > 1 {
            for id in ids {
                if let Err(error) = self.objects.get_mut(&id).unwrap().0.mark_as_maybe_freed() {
                    possible_double_free_ids.push((id.clone(), error));
                }
            }
        } else if let Some(id) = ids.get(0) {
            if let Err(error) = self.objects.get_mut(id).unwrap().0.mark_as_freed() {
                possible_double_free_ids.push((id.clone(), error));
            }
        }
        if possible_double_free_ids.is_empty() {
            Ok(())
        } else {
            Err(possible_double_free_ids)
        }
    }
}
