//! Methods of [`State`] for manipulating abstract IDs.

use super::*;
use crate::analysis::pointer_inference::object::AbstractObject;
use crate::analysis::pointer_inference::POINTER_RECURSION_DEPTH_LIMIT;

impl State {
    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs reachable through concrete pointers contained in them to the set of IDs.
    ///
    /// This uses an underapproximation of the referenced IDs of a memory object,
    /// i.e. IDs may be missing if the analysis lost track of the corresponding pointer.
    pub fn add_directly_reachable_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_underapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs contained in them to the set of IDs.
    ///
    /// This uses an overapproximation of the referenced IDs of a memory object,
    /// i.e. for a memory object it may add IDs as possible references
    /// where the corresponding reference is not longer present in the memory object.
    pub fn add_recursively_referenced_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_overapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Add the given `param_object` from the callee state to `self`
    /// (where `self` represents the state after returning from the callee).
    ///
    /// `param_value_at_call` is the value that the parameter had at the callsite.
    /// It is assumed that all IDs contained in the `param_object` are already replaced with values relative to the caller.
    ///
    /// If the `param_object` corresponds to a unique object in `self`
    /// then the contents of that object are overwritten with those of `param_object`.
    /// Else the contents are only merged with all possible caller objects,
    /// since the exact object that corresponds to the callee object is unknown.
    pub fn add_param_object_from_callee(
        &mut self,
        param_object: AbstractObject,
        param_value_at_call: &Data,
    ) -> Result<(), Error> {
        if let Some((caller_id, offset)) = param_value_at_call.get_if_unique_target() {
            // The corresponding caller object is unique
            if let Some(caller_object) = self.memory.get_object_mut(caller_id) {
                caller_object.overwrite_with(&param_object, offset);
            } else {
                return Err(anyhow!("Missing caller memory object"));
            }
        } else {
            // We cannot exactly identify to which caller object the callee object corresponds.
            for (caller_id, offset) in param_value_at_call.get_relative_values() {
                if let Some(caller_object) = self.memory.get_object_mut(caller_id) {
                    let mut param_object = param_object.clone();
                    param_object.add_offset_to_all_indices(offset);
                    *caller_object = caller_object.merge(&param_object);
                } else {
                    return Err(anyhow!("Missing caller memory object"));
                }
            }
        }
        Ok(())
    }

    /// Remove the non-parameter IDs given in the targets of the location to data map.
    ///
    /// Note that this function assumes (but does not check)
    /// that these IDs are only contained in the abstract locations given by the keys of the location to data map.
    pub fn remove_old_ids_to_unified_objects(
        &mut self,
        location_to_data_map: &BTreeMap<AbstractIdentifier, Data>,
    ) {
        let mut ids_to_remove = BTreeSet::new();
        for value in location_to_data_map.values() {
            for (id, offset) in value.get_relative_values() {
                if id.get_tid() != self.get_fn_tid() || !id.get_path_hints().is_empty() {
                    ids_to_remove.insert(id.clone());
                }
            }
        }
        for value in self.register.values_mut() {
            value.remove_ids(&ids_to_remove);
            if value.is_empty() {
                *value = Data::new_top(value.bytesize());
            }
        }
        for object in self.memory.iter_objects_mut() {
            object.remove_ids(&ids_to_remove);
        }
    }

    pub fn insert_pointers_to_unified_objects(
        &mut self,
        location_to_data_map: &BTreeMap<AbstractIdentifier, Data>,
    ) {
        todo!()
    }

    /// Merge the target objects that are non-parameter objects for the given location to data mapping.
    /// Return the results as a location to memory object map.
    ///
    /// This function is a step in the process of unifying callee-originating memory objects on a return instruction.
    /// The memory objects are also marked as unique, because they will represent a unique object in the caller.
    pub fn generate_target_objects_for_new_locations(
        &self,
        location_to_data_map: &BTreeMap<AbstractIdentifier, Data>,
    ) -> BTreeMap<AbstractIdentifier, AbstractObject> {
        let mut location_to_object_map: BTreeMap<AbstractIdentifier, AbstractObject> =
            BTreeMap::new();
        for (location_id, value) in location_to_data_map {
            let mut new_object: Option<AbstractObject> = None;
            'target_loop: for (target_id, target_offset) in value.get_relative_values() {
                if target_id.get_tid() == self.get_fn_tid() || !self.memory.contains(target_id) {
                    continue 'target_loop;
                }
                let target_offset = match target_offset.try_to_offset() {
                    Ok(offset) => offset,
                    Err(_) => {
                        match &mut new_object {
                            Some(object) => object.assume_arbitrary_writes(&BTreeSet::new()),
                            None => {
                                new_object =
                                    Some(AbstractObject::new(None, self.stack_id.bytesize()))
                            }
                        }
                        continue 'target_loop;
                    }
                };
                let target_object = self.memory.get_object(target_id).unwrap();
                let mut target_object = target_object.clone();
                target_object
                    .add_offset_to_all_indices(&Bitvector::from_i64(-target_offset).into());
                match &mut new_object {
                    None => new_object = Some(target_object),
                    Some(object) => *object = object.merge(&target_object),
                }
            }
            let mut new_object =
                new_object.unwrap_or_else(|| AbstractObject::new(None, self.stack_id.bytesize()));
            new_object.mark_as_unique();
            new_object.set_object_type(None);

            location_to_object_map.insert(location_id.clone(), new_object);
        }
        location_to_object_map
    }

    /// Filter out those locations from the location to pointer data map
    /// whose non-parameter object targets intersect with any of the other locations.
    ///
    /// Note that this does not filter out locations whose targets contain the `Top` flag,
    /// despite the fact that these locations theoretically may point to the same non-parameter object.
    /// I.e. we trade soundness in the general case for exactness in the common case here.
    pub fn filter_location_to_pointer_data_map(
        &self,
        location_to_data_map: &mut BTreeMap<AbstractIdentifier, Data>,
    ) {
        let mut visited_targets = HashSet::new();
        let mut non_unique_targets = HashSet::new();
        for value in location_to_data_map.values() {
            for (id, offset) in value.get_relative_values() {
                if id.get_tid() != self.get_fn_tid() && self.memory.contains(id) {
                    if !visited_targets.insert(id.clone()) {
                        non_unique_targets.insert(id.clone());
                    }
                }
            }
        }
        location_to_data_map.retain(|location, value| {
            for (id, offset) in value.get_relative_values() {
                if non_unique_targets.contains(id) {
                    return false;
                }
            }
            true
        })
    }

    /// Generate a map from abstract locations pointing to non-parameter memory objects
    /// to the data represented by the abstract location in the current state.
    ///
    /// The abstract locations get different TIDs depending on the root of the location:
    /// - If the root is a return register, then the TID is given by the provided `call_tid`.
    /// - If the root is a parameter memory object, then the TID is given by appending the suffix `_param` to the `call_TID`.
    ///   Since parameter and return register can overlap, the abstract IDs would overlap
    ///   if one would use the same TID in both cases.
    ///
    /// This function assumes that
    /// [`State::minimize_before_return_instruction`](crate::analysis::pointer_inference::State::minimize_before_return_instruction)
    /// has been called on `self` beforehand.
    pub fn map_abstract_locations_to_pointer_data(
        &self,
        call_tid: &Tid,
    ) -> BTreeMap<AbstractIdentifier, Data> {
        let mut location_to_data_map = BTreeMap::new();
        // Add root IDs based on return registers (all other registers should be cleared from the state)
        for (var, value) in self.register.iter() {
            if !var.is_temp && self.contains_non_param_pointer(value) {
                let location = AbstractLocation::from_var(var).unwrap();
                location_to_data_map.insert(
                    AbstractIdentifier::new(call_tid.clone(), location),
                    value.clone(),
                );
            }
        }
        // Add root locations based on parameter objects
        for (object_id, object) in self.memory.iter() {
            if object_id.get_tid() == self.get_fn_tid()
                && object_id.get_location().recursion_depth() < POINTER_RECURSION_DEPTH_LIMIT
            {
                for (index, value) in object.get_mem_region().iter() {
                    if self.contains_non_param_pointer(value) {
                        let location = object_id
                            .get_location()
                            .clone()
                            .dereferenced(value.bytesize(), self.stack_id.bytesize())
                            .with_offset_addendum(*index);
                        location_to_data_map.insert(
                            AbstractIdentifier::new(
                                call_tid.clone().with_id_suffix("_param"),
                                location,
                            ),
                            value.clone(),
                        );
                    }
                }
            }
        }
        // Add derived locations based on the root locations
        let mut locations_to_derive = location_to_data_map.clone();
        while let Some((location_id, location_data)) = locations_to_derive.pop_first() {
            if location_id.get_location().recursion_depth() >= POINTER_RECURSION_DEPTH_LIMIT {
                continue;
            }
            'data_target_loop: for (object_id, object_offset) in location_data.get_relative_values()
            {
                if object_id.get_tid() == self.get_fn_tid() {
                    // Ignore parameter objects
                    continue 'data_target_loop;
                }
                let object_offset = match object_offset.try_to_offset() {
                    Ok(offset) => offset,
                    Err(_) => continue 'data_target_loop,
                };
                let mem_object = match self.memory.get_object(object_id) {
                    Some(object) => object,
                    None => continue 'data_target_loop,
                };
                for (elem_offset, elem_data) in mem_object.get_mem_region().iter() {
                    if self.contains_non_param_pointer(elem_data) {
                        // We want to create a new abstract location for this element.
                        // But the same abstract location may already exist, so we may have to merge values instead.
                        let new_location_offset = *elem_offset - object_offset; // TODO: Check correctness of this offset!
                        let new_location = location_id
                            .get_location()
                            .clone()
                            .dereferenced(elem_data.bytesize(), self.stack_id.bytesize())
                            .with_offset_addendum(new_location_offset);
                        let new_location_id =
                            AbstractIdentifier::new(location_id.get_tid().clone(), new_location);
                        let new_location_data = elem_data.clone();
                        location_to_data_map
                            .entry(new_location_id.clone())
                            .and_modify(|loc_data| *loc_data = loc_data.merge(&new_location_data))
                            .or_insert(new_location_data.clone());
                        locations_to_derive
                            .entry(new_location_id.clone())
                            .and_modify(|loc_data| *loc_data = loc_data.merge(&new_location_data))
                            .or_insert(new_location_data);
                        todo!(); // We *cannot* derive nested non-root IDs in parameter objects!
                                 // These IDs would not be unique regarding either their root (a nested param or another nested return value)
                                 // or their ID itself (if both possible roots exist).
                                 // So we probably have to remove the `and_modify` variant above.
                                 // And the deriving of nested variants for param object based locations!
                    }
                }
            }
        }
        location_to_data_map
    }

    /// Returns `true` if the value contains at least one reference to a non-parameter
    /// (and non-stack) memory object tracked by the current state.
    fn contains_non_param_pointer(&self, value: &Data) -> bool {
        for id in value.referenced_ids() {
            if id.get_tid() != self.get_fn_tid() && self.memory.contains(id) {
                return true;
            }
        }
        false
    }
}
