use super::*;
use crate::analysis::function_signature::AccessPattern;

impl<'a> Context<'a> {
    /// Create a map that maps each abstract ID known to the callee
    /// to the value that represents it in the caller.
    ///
    /// For parameter IDs this is the value of the parameter on function call.
    /// For IDs of objects created in the callee it is the ID itself.
    /// For other IDs (including the callee stack frame ID) it is a `Top` value,
    /// i.e. the value of the ID should be unknown to the caller.
    ///
    /// Note that this function assumes that callee-originating IDs have already been renamed
    /// to the name they should represent in the caller beforehand.
    pub fn create_callee_id_to_caller_data_map(
        &self,
        state_before_call: &State,
        state_before_return: &State,
    ) -> BTreeMap<AbstractIdentifier, Data> {
        let stack_register = &self.project.stack_pointer_register;
        let mut id_map = BTreeMap::new();
        let callee_tid = state_before_return.get_fn_tid();
        if let Some(callee_fn_sig) = self.fn_signatures.get(callee_tid) {
            for param in callee_fn_sig.parameters.keys() {
                let param_id = AbstractIdentifier::new(callee_tid.clone(), param.clone());
                let param_value = state_before_call
                    .eval_abstract_location(param, &self.project.runtime_memory_image);
                id_map.insert(param_id, param_value);
            }
            for global_param in callee_fn_sig.global_parameters.keys() {
                let global_param_id =
                    AbstractIdentifier::new(callee_tid.clone(), global_param.clone());
                let global_param_value = state_before_call
                    .eval_abstract_location(global_param, &self.project.runtime_memory_image);
                id_map.insert(global_param_id, global_param_value);
            }
        }
        for object_id in state_before_return.memory.get_all_object_ids() {
            if object_id.get_tid() != callee_tid || !object_id.get_path_hints().is_empty() {
                // Object is neither a parameter object nor the stack frame of the callee.
                id_map.insert(
                    object_id.clone(),
                    Data::from_target(
                        object_id,
                        Bitvector::zero(stack_register.size.into()).into(),
                    ),
                );
            }
        }
        id_map.insert(
            state_before_return.stack_id.clone(),
            Data::new_top(stack_register.size),
        );
        // Also insert the global memory ID to the map.
        id_map.insert(
            state_before_return.get_global_mem_id(),
            Data::from_target(
                state_before_call.get_global_mem_id(),
                Bitvector::zero(stack_register.size.into()).into(),
            ),
        );

        id_map
    }

    /// Create a map that maps callee IDs to the value assigned to it in the caller after a return instruction.
    ///
    /// This is *not* the map used in the internal `update_return` handling.
    /// Instead, the created map combines several ID renaming steps used internally into one renaming map.
    /// The map is intended for use in other analyses depending on the PointerInference,
    /// but not in the PointerInference itself.
    pub fn create_full_callee_id_to_caller_data_map(
        &self,
        state_before_call: &State,
        state_before_return: &State,
        call_tid: &Tid,
    ) -> BTreeMap<AbstractIdentifier, Data> {
        let cconv = &self.project.program.term.subs[state_before_return.get_fn_tid()]
            .term
            .calling_convention;
        let cconv = match self.project.get_specific_calling_convention(cconv) {
            Some(cconv) => cconv,
            None => {
                return BTreeMap::new();
            }
        };
        let callee_fn_sig = self
            .fn_signatures
            .get(state_before_return.get_fn_tid())
            .unwrap();
        let mut minimized_return_state = state_before_return.clone();
        minimized_return_state.minimize_before_return_instruction(callee_fn_sig, cconv);
        let mut location_to_data_map =
            minimized_return_state.map_abstract_locations_to_pointer_data(call_tid);
        minimized_return_state.filter_location_to_pointer_data_map(&mut location_to_data_map);
        let mut replacement_map =
            minimized_return_state.get_id_to_unified_ids_replacement_map(&location_to_data_map);
        let unified_to_caller_replacement_map =
            self.create_callee_id_to_caller_data_map(state_before_call, &minimized_return_state);
        // In the ID-to-unified-ID map replace parameter IDs with their corresponding values in the caller.
        for value in replacement_map.values_mut() {
            value.replace_all_ids(&unified_to_caller_replacement_map);
        }
        // Add all parameter IDs to the map
        let callee_tid = state_before_return.get_fn_tid();
        for (id, value) in unified_to_caller_replacement_map {
            if id.get_tid() == callee_tid && id.get_path_hints().is_empty() {
                replacement_map.insert(id, value);
            }
        }
        replacement_map
    }

    /// Create a map from the parameter IDs (of the function that the given state corresponds to)
    /// to the corresponding access patterns.
    pub fn create_id_to_access_pattern_map(
        &self,
        state: &State,
    ) -> BTreeMap<AbstractIdentifier, &AccessPattern> {
        let mut id_to_access_pattern_map = BTreeMap::new();
        let fn_tid = state.get_fn_tid();
        let callee_fn_sig = self.fn_signatures.get(fn_tid).unwrap();
        for (param, access_pattern) in &callee_fn_sig.parameters {
            let param_id = AbstractIdentifier::new(fn_tid.clone(), param.clone());
            id_to_access_pattern_map.insert(param_id.clone(), access_pattern);
        }
        for (param, access_pattern) in &callee_fn_sig.global_parameters {
            let param_id = AbstractIdentifier::new(fn_tid.clone(), param.clone());
            id_to_access_pattern_map.insert(param_id.clone(), access_pattern);
        }

        id_to_access_pattern_map
    }

    /// Identify caller IDs used in more than one parameter,
    /// for which at least one parameter has write access to the corresponding memory object.
    /// For these IDs the analysis in the callee is unsound for the corresponding callsite!
    pub fn get_unsound_caller_ids(
        &self,
        callee_id_to_caller_data_map: &BTreeMap<AbstractIdentifier, Data>,
        callee_id_to_access_pattern_map: &BTreeMap<AbstractIdentifier, &AccessPattern>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut ids_touched = BTreeSet::new();
        let mut ids_modified = BTreeSet::new();
        let mut unsound_caller_ids = BTreeSet::new();
        for (callee_id, access_pattern) in callee_id_to_access_pattern_map {
            for id in callee_id_to_caller_data_map
                .get(callee_id)
                .unwrap()
                .referenced_ids()
            {
                if ids_modified.get(id).is_some()
                    || (access_pattern.is_mutably_dereferenced() && ids_touched.get(id).is_some())
                {
                    unsound_caller_ids.insert(id.clone());
                }
                ids_touched.insert(id.clone());
                if access_pattern.is_mutably_dereferenced() {
                    ids_modified.insert(id.clone());
                }
            }
        }

        unsound_caller_ids
    }
}
