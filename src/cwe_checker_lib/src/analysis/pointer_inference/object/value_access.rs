use super::*;

impl AbstractObject {
    /// Check whether a memory access to the abstract object at the given offset
    /// and with the given size of the accessed value is contained in the bounds of the memory object.
    /// If `offset` contains more than one possible index value,
    /// then only return `true` if the access is contained in the abstract object for all possible offset values.
    ///
    /// If `offset` is a `Top` value, then the function assumes this to be due to analysis inaccuracies
    /// and does not flag them as possible out-of-bounds access.
    pub fn access_contained_in_bounds(&self, offset: &ValueDomain, size: ByteSize) -> bool {
        if offset.is_top() {
            // Currently TOP offsets happen a lot due to inaccuracies in the analysis.
            // So for the time being we do not flag them as possible CWEs.
            return true;
        }
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
}
