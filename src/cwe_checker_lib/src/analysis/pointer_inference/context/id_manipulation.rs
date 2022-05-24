use super::*;
use crate::analysis::function_signature::AccessPattern;

impl<'a> Context<'a> {
    /// Create a map that maps each abstract ID known to the callee
    /// to the value that represents it in the caller.
    ///
    /// For parameter IDs this is the value of the parameter on function call.
    /// For IDs of objects created in the callee it is the ID together with a path hint given by the call TID.
    /// For other IDs (including the callee stack frame ID) it is a `Top` value,
    /// i.e. the value of the ID should be unknown to the caller.
    pub fn create_callee_id_to_caller_data_map(
        &self,
        state_before_call: &State,
        state_before_return: &State,
        call_tid: &Tid,
    ) -> BTreeMap<AbstractIdentifier, Data> {
        let stack_register = &self.project.stack_pointer_register;
        let mut id_map = BTreeMap::new();
        let callee_tid = state_before_return.get_fn_tid();
        let callee_fn_sig = self.fn_signatures.get(callee_tid).unwrap();
        for param in callee_fn_sig.parameters.keys() {
            let param_id = AbstractIdentifier::from_arg(callee_tid, param);
            if let Ok(param_value) =
                state_before_call.eval_parameter_arg(param, &self.project.runtime_memory_image)
            {
                id_map.insert(param_id, param_value);
            } else {
                id_map.insert(param_id, Data::new_top(param.bytesize()));
            }
        }
        for object_id in state_before_return.memory.get_all_object_ids() {
            if object_id.get_tid() != callee_tid || !object_id.get_path_hints().is_empty() {
                // Object is neither a parameter object nor the stack frame of the callee.
                if let Ok(new_object_id) = object_id.with_path_hint(call_tid.clone()) {
                    id_map.insert(
                        object_id,
                        Data::from_target(
                            new_object_id,
                            Bitvector::zero(stack_register.size.into()).into(),
                        ),
                    );
                } else {
                    id_map.insert(object_id, Data::new_top(stack_register.size));
                }
            }
        }
        id_map.insert(
            state_before_return.stack_id.clone(),
            Data::new_top(stack_register.size),
        );

        id_map
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
            let param_id = AbstractIdentifier::from_arg(fn_tid, param);
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
