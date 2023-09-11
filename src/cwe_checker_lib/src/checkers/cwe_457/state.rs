use super::init_status::InitializationStatus;
use crate::{
    abstract_domain::{AbstractIdentifier, MemRegion},
    intermediate_representation::ByteSize,
};
use std::collections::HashMap;

/// Contains tracked objects and allows manipulation of them.
/// The used `MemRegion<InitializationStatus>>` does not contain `InitializationStatus::Uninit` at all.
/// Values not contained are interpreted as `Uninit` as an optimization.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct State {
    pub tracked_objects: HashMap<AbstractIdentifier, MemRegion<InitializationStatus>>,
}

impl State {
    /// Creates a new, empty state.
    pub fn new() -> State {
        State {
            tracked_objects: HashMap::new(),
        }
    }

    /// Adds a new, uninitialized memory objects to the state.
    pub fn new_with_id(id: AbstractIdentifier, address_bytesize: ByteSize) -> State {
        let mut state = State::new();
        state
            .tracked_objects
            .insert(id, MemRegion::new(address_bytesize));
        state
    }

    // Adds new entry with empty MemRegion, if the entry does not exists.
    pub fn add_new_object(&mut self, id: AbstractIdentifier, address_bytesize: ByteSize) {
        self.tracked_objects
            .entry(id)
            .or_insert_with(|| MemRegion::new(address_bytesize));
    }

    /// Inserts `status` at specific offset in a **tracked** memory object.
    pub fn insert_single_offset(
        &mut self,
        id: &AbstractIdentifier,
        offset: i64,
        status: InitializationStatus,
    ) {
        if let Some(mem_region) = self.tracked_objects.get_mut(id) {
            mem_region.insert_at_byte_index(status, offset)
        }
    }

    pub fn merge_precise_single_offset(
        &mut self,
        id: &AbstractIdentifier,
        offset: i64,
        status: &InitializationStatus,
    ) {
        if let Some(mem_region) = self.tracked_objects.get_mut(id) {
            mem_region.merge_precise_at_byte_index(offset, status);
        }
    }

    /// Copies a range of offsets from a tracked source object to a tracked target object.
    ///
    /// Return `Err` if the provided objects are not contained in `tracked_objects`.
    pub fn copy_range_from_other_object(
        &mut self,
        source: &AbstractIdentifier,
        source_offset: i64,
        target: &AbstractIdentifier,
        target_offset: i64,
        size: u64,
    ) -> Result<(), String> {
        let source_mem_region = self
            .tracked_objects
            .get(source)
            .ok_or("Source identifier is not tracked.")?
            .clone();
        if !self.tracked_objects.contains_key(target) {
            return Err("Source identifier is not tracked.".into());
        }
        for i in 0..=size as i64 {
            let status = source_mem_region.get_init_status_at_byte_index(source_offset + i);
            self.insert_single_offset(target, target_offset + i, status);
        }

        Ok(())
    }

    /// Returns true if an tracked memory object is entirely uninitialized.
    pub fn object_is_uninitialized(&self, id: &AbstractIdentifier) -> bool {
        if let Some(mem_region) = self.tracked_objects.get(id) {
            return mem_region.entry_map().is_empty();
        }
        false
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for id in self.tracked_objects.keys() {
            out.push_str(&format!("{}\n", id));
            if let Some(mem_region) = self.tracked_objects.get(id) {
                for (offset, status) in mem_region.entry_map() {
                    out.push_str(&format!("\t{}\t : \t {:?}\n", offset, status));
                }
            }
        }
        out
    }
}
