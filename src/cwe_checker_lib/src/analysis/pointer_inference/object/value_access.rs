use super::*;

impl AbstractObject {
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
