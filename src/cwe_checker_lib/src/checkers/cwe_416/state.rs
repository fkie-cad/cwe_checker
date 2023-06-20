use crate::analysis::pointer_inference::State as PiState;
use crate::{
    abstract_domain::{AbstractDomain, AbstractIdentifier, DomainMap, UnionMergeStrategy},
    analysis::pointer_inference::Data,
    prelude::*,
};
use std::collections::BTreeMap;

/// The state of a memory object for which at least one possible call to a `free`-like function was detected.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
enum ObjectState {
    /// The object is already freed, i.e. pointers to it are dangling.
    /// The associated TID denotes the point in time when the object was freed.
    Dangling(Tid),
    /// The object is already freed and a use-after-free CWE message for it was already generated.
    /// This object state is used to prevent duplicate CWE warnings with the same root cause.
    AlreadyFlagged,
}

impl AbstractDomain for ObjectState {
    /// Merge two object states.
    /// If both object states are dangling then use the source TID of `self` in the result.
    fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            (ObjectState::AlreadyFlagged, _) | (_, ObjectState::AlreadyFlagged) => {
                ObjectState::AlreadyFlagged
            }
            (ObjectState::Dangling(tid), ObjectState::Dangling(other_tid)) => {
                ObjectState::Dangling(std::cmp::min(tid, other_tid).clone())
            }
        }
    }

    /// The `Top` element for object states is a dangling pointer.
    fn is_top(&self) -> bool {
        matches!(self, ObjectState::Dangling(_))
    }
}

/// The `State` currently only keeps track of the list of TIDs of memory object that may have been freed already
/// together with the corresponding object states.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    pub current_fn_tid: Tid,
    dangling_objects: DomainMap<AbstractIdentifier, ObjectState, UnionMergeStrategy>,
}

impl State {
    /// Create a new, empty state, i.e. a state without any object marked as already freed.
    pub fn new(current_fn_tid: Tid) -> State {
        State {
            current_fn_tid,
            dangling_objects: BTreeMap::new().into(),
        }
    }

    /// Return whether the given object ID is already flagged in this state,
    /// i.e. whether a CWE warning was already generated for this object.
    pub fn is_id_already_flagged(&self, object_id: &AbstractIdentifier) -> bool {
        self.dangling_objects.get(object_id) == Some(&ObjectState::AlreadyFlagged)
    }

    /// If the given `object_id` represents a dangling object, return the TID of the site where it was freed.
    pub fn get_free_tid_if_dangling(&self, object_id: &AbstractIdentifier) -> Option<&Tid> {
        if let Some(ObjectState::Dangling(free_tid)) = self.dangling_objects.get(object_id) {
            Some(free_tid)
        } else {
            None
        }
    }

    /// Check the given address on whether it may point to already freed memory.
    /// For each possible dangling pointer target the abstract ID of the object
    /// and the TID of the corresponding site where the object was freed is returned.
    /// The object states of corresponding memory objects are set to [`ObjectState::AlreadyFlagged`]
    /// to prevent reporting duplicate CWE messages with the same root cause.
    pub fn check_address_for_use_after_free(
        &mut self,
        address: &Data,
    ) -> Option<Vec<(AbstractIdentifier, Tid)>> {
        let mut free_ids_of_dangling_pointers = Vec::new();
        for id in address.get_relative_values().keys() {
            if let Some(ObjectState::Dangling(free_id)) = self.dangling_objects.get(id) {
                free_ids_of_dangling_pointers.push((id.clone(), free_id.clone()));

                self.dangling_objects
                    .insert(id.clone(), ObjectState::AlreadyFlagged);
            }
        }
        if free_ids_of_dangling_pointers.is_empty() {
            None
        } else {
            Some(free_ids_of_dangling_pointers)
        }
    }

    /// All TIDs that the given `param` may point to are marked as freed, i.e. pointers to them are dangling.
    /// For each ID that was already marked as dangling return a string describing the root cause of a possible double free bug.
    pub fn handle_param_of_free_call(
        &mut self,
        call_tid: &Tid,
        param: &Data,
        pi_state: &PiState,
    ) -> Option<Vec<(AbstractIdentifier, Tid)>> {
        // FIXME: This function could also generate debug log messages whenever nonsensical information is detected.
        // E.g. stack frame IDs or non-zero ID offsets can be indicators of other bugs.
        let mut warnings = Vec::new();
        for id in param.get_relative_values().keys() {
            if pi_state.memory.is_unique_object(id).ok() == Some(false) {
                // FIXME: We cannot distinguish different objects represented by the same ID.
                // So to avoid producing lots of false positive warnings
                // we ignore these cases by not marking these IDs as freed.
                continue;
            }
            if let Some(ObjectState::Dangling(old_free_id)) = self
                .dangling_objects
                .insert(id.clone(), ObjectState::Dangling(call_tid.clone()))
            {
                warnings.push((id.clone(), old_free_id.clone()));
            }
        }
        if !warnings.is_empty() {
            Some(warnings)
        } else {
            None
        }
    }

    /// Add objects that were freed in the callee of a function call to the list of dangling pointers of `self`.
    /// May return a list of warnings if cases of possible double frees are detected,
    /// i.e. if an already freed object may also have been freed in the callee.
    pub fn collect_freed_objects_from_called_function(
        &mut self,
        state_before_return: &State,
        id_replacement_map: &BTreeMap<AbstractIdentifier, Data>,
        call_tid: &Tid,
        pi_state: &PiState,
    ) {
        for (callee_id, callee_object_state) in state_before_return.dangling_objects.iter() {
            if let Some(caller_value) = id_replacement_map.get(callee_id) {
                for caller_id in caller_value.get_relative_values().keys() {
                    if pi_state.memory.is_unique_object(caller_id).ok() != Some(false) {
                        // FIXME: We cannot distinguish different objects represented by the same ID.
                        // So to avoid producing lots of false positive warnings we ignore these cases.
                        match (callee_object_state, self.dangling_objects.get(caller_id)) {
                            // Case 1: The dangling object is unknown to the caller, so we add it.
                            (ObjectState::Dangling(_), None)
                            | (ObjectState::AlreadyFlagged, None) => {
                                self.dangling_objects.insert(
                                    caller_id.clone(),
                                    ObjectState::Dangling(call_tid.clone()),
                                );
                            }
                            // Case 2: The dangling object is already known to the caller.
                            // If this were a case of Use-After-Free, then this should have been flagged when checking the call parameters.
                            // Thus we can simply leave the object state as it is.
                            (_, Some(ObjectState::Dangling(_)))
                            | (_, Some(&ObjectState::AlreadyFlagged)) => (),
                        }
                    }
                }
            }
        }
    }
}

impl AbstractDomain for State {
    /// Merge two states.
    fn merge(&self, other: &Self) -> Self {
        State {
            current_fn_tid: self.current_fn_tid.clone(),
            dangling_objects: self.dangling_objects.merge(&other.dangling_objects),
        }
    }

    /// Always returns false. The state has no logical `Top` element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a more compact json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    #[allow(dead_code)]
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut state_map = Map::new();
        state_map.insert(
            "current_function".to_string(),
            Value::String(format!("{}", self.current_fn_tid)),
        );
        for (id, object_state) in self.dangling_objects.iter() {
            if let ObjectState::Dangling(free_tid) = object_state {
                state_map.insert(
                    format!("{id}"),
                    Value::String(format!("Dangling({free_tid})")),
                );
            } else {
                state_map.insert(
                    format!("{id}"),
                    Value::String("Already flagged".to_string()),
                );
            }
        }
        Value::Object(state_map)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{bitvec, intermediate_representation::parsing, variable};
    use std::collections::BTreeSet;

    impl State {
        pub fn mock(
            current_fn_tid: Tid,
            dangling_ids: &[(AbstractIdentifier, Tid)],
            already_flagged_ids: &[AbstractIdentifier],
        ) -> Self {
            let mut state = State::new(current_fn_tid);
            for (id, free_id) in dangling_ids.iter() {
                state
                    .dangling_objects
                    .insert(id.clone(), ObjectState::Dangling(free_id.clone()));
            }
            for id in already_flagged_ids.iter() {
                state
                    .dangling_objects
                    .insert(id.clone(), ObjectState::AlreadyFlagged);
            }
            state
        }
    }

    #[test]
    fn test_check_address_for_use_after_free() {
        let mut state = State::new(Tid::new("current_fn"));
        state.dangling_objects.insert(
            AbstractIdentifier::mock("obj_id", "RAX", 8),
            ObjectState::Dangling(Tid::new("free_call")),
        );
        state.dangling_objects.insert(
            AbstractIdentifier::mock("flagged_obj_id", "RAX", 8),
            ObjectState::AlreadyFlagged,
        );
        let address = Data::mock_from_target_map(BTreeMap::from([
            (
                AbstractIdentifier::mock("obj_id", "RAX", 8),
                Bitvector::from_i64(0).into(),
            ),
            (
                AbstractIdentifier::mock("flagged_obj_id", "RAX", 8),
                Bitvector::from_i64(0).into(),
            ),
        ]));
        // Check that one warning is generated for the dangling pointer
        // and that afterwards all corresponding IDs are marked as already flagged.
        assert_eq!(
            state
                .check_address_for_use_after_free(&address)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            *state
                .dangling_objects
                .get(&AbstractIdentifier::mock("obj_id", "RAX", 8))
                .unwrap(),
            ObjectState::AlreadyFlagged
        );
        assert_eq!(
            *state
                .dangling_objects
                .get(&AbstractIdentifier::mock("flagged_obj_id", "RAX", 8))
                .unwrap(),
            ObjectState::AlreadyFlagged
        );
    }

    #[test]
    fn test_handle_param_of_free_call() {
        let mut state = State::new(Tid::new("current_fn"));
        let param = Data::from_target(
            AbstractIdentifier::mock("obj_id", "RAX", 8),
            bitvec!("0:8").into(),
        );
        let pi_state = PiState::new(&variable!("RSP:8"), Tid::new("call"), BTreeSet::new());
        // Check that the parameter is correctly marked as freed in the state.
        assert!(state
            .handle_param_of_free_call(&Tid::new("free_call"), &param, &pi_state)
            .is_none());
        assert_eq!(
            *state
                .dangling_objects
                .get(&AbstractIdentifier::mock("obj_id", "RAX", 8))
                .unwrap(),
            ObjectState::Dangling(Tid::new("free_call"))
        );
        // Check that a second free operation yields a double free warning.
        assert!(state
            .handle_param_of_free_call(&Tid::new("free_call"), &param, &pi_state)
            .is_some());
    }

    #[test]
    fn test_collect_freed_objects_from_called_function() {
        let mut state = State::new(Tid::new("current_fn"));
        let mut state_before_return = State::new(Tid::new("callee_fn_tid"));
        state_before_return.dangling_objects.insert(
            AbstractIdentifier::mock("callee_obj_tid", "RAX", 8),
            ObjectState::Dangling(Tid::new("free_tid")),
        );
        let pi_state = PiState::new(&variable!("RSP:8"), Tid::new("call"), BTreeSet::new());
        let id_replacement_map = BTreeMap::from([(
            AbstractIdentifier::mock("callee_obj_tid", "RAX", 8),
            Data::from_target(
                AbstractIdentifier::mock("caller_tid", "RBX", 8),
                bitvec!("42:8").into(),
            ),
        )]);
        // Check that the callee object ID is correctly translated to a caller object ID
        state.collect_freed_objects_from_called_function(
            &state_before_return,
            &id_replacement_map,
            &Tid::new("call_tid"),
            &pi_state,
        );
        assert_eq!(state.dangling_objects.len(), 1);
        assert_eq!(
            state
                .dangling_objects
                .get(&AbstractIdentifier::mock("caller_tid", "RBX", 8))
                .unwrap(),
            &ObjectState::Dangling(Tid::new("call_tid"))
        );
    }
}
