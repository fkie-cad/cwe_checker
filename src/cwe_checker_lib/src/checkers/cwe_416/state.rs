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
            (ObjectState::Dangling(tid), ObjectState::Dangling(_)) => {
                ObjectState::Dangling(tid.clone())
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
    dangling_objects: DomainMap<AbstractIdentifier, ObjectState, UnionMergeStrategy>,
}

impl State {
    /// Create a new, empty state, i.e. a state without any object marked as already freed.
    pub fn new() -> State {
        State {
            dangling_objects: BTreeMap::new().into(),
        }
    }

    /// Check the given address on whether it may point to already freed memory.
    /// For each possible dangling pointer target a string describing the root cause is returnen.
    /// The object states of corresponding memory objects are set to [`ObjectState::AlreadyFlagged`]
    /// to prevent reporting duplicate CWE messages with the same root cause.
    pub fn check_address_for_use_after_free(&mut self, address: &Data) -> Option<Vec<String>> {
        let mut free_ids_of_dangling_pointers = Vec::new();
        for id in address.get_relative_values().keys() {
            if let Some(ObjectState::Dangling(free_id)) = self.dangling_objects.get(id) {
                free_ids_of_dangling_pointers.push(format!(
                    "Accessed ID {} may have been already freed at {}",
                    id, free_id
                ));

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
    ) -> Option<Vec<String>> {
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
                warnings.push(format!(
                    "Object {} may have been freed before at {}.",
                    id, old_free_id
                ));
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
    ) -> Option<Vec<String>> {
        let mut warnings = Vec::new();
        for (callee_id, callee_object_state) in state_before_return.dangling_objects.iter() {
            if let Some(caller_value) = id_replacement_map.get(callee_id) {
                for caller_id in caller_value.get_relative_values().keys() {
                    if pi_state.memory.is_unique_object(caller_id).ok() != Some(false) {
                        // FIXME: We cannot distinguish different objects represented by the same ID.
                        // So to avoid producing lots of false positive warnings we ignore these cases.
                        match (callee_object_state, self.dangling_objects.get(caller_id)) {
                            (ObjectState::Dangling(_), None)
                            | (ObjectState::AlreadyFlagged, None) => {
                                self.dangling_objects.insert(
                                    caller_id.clone(),
                                    ObjectState::Dangling(call_tid.clone()),
                                );
                            }
                            (ObjectState::Dangling(_), Some(ObjectState::Dangling(_)))
                            | (ObjectState::AlreadyFlagged, Some(&ObjectState::Dangling(_))) => {
                                warnings.push(format!("Callee ID {} corresponding to caller ID {} may be freed in the callee", callee_id, caller_id));
                                self.dangling_objects
                                    .insert(caller_id.clone(), ObjectState::AlreadyFlagged);
                            }
                            (_, Some(&ObjectState::AlreadyFlagged)) => (), // To avoid subsequent errors we do not flag this case separately.
                        }
                    }
                }
            }
        }
        if !warnings.is_empty() {
            Some(warnings)
        } else {
            None
        }
    }
}

impl AbstractDomain for State {
    /// Merge two states.
    fn merge(&self, other: &Self) -> Self {
        State {
            dangling_objects: self.dangling_objects.merge(&other.dangling_objects),
        }
    }

    /// Always returns false. The state has no logical `Top` element.
    fn is_top(&self) -> bool {
        false
    }
}

#[cfg(test)]
pub mod tests {
    use crate::intermediate_representation::Variable;

    use super::*;

    #[test]
    fn test_check_address_for_use_after_free() {
        let mut state = State::new();
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
        let mut state = State::new();
        let param = Data::from_target(
            AbstractIdentifier::mock("obj_id", "RAX", 8),
            Bitvector::from_i64(0).into(),
        );
        let pi_state = PiState::new(&Variable::mock("RSP", 8), Tid::new("call"));
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
        let mut state = State::new();
        let mut state_before_return = State::new();
        state_before_return.dangling_objects.insert(
            AbstractIdentifier::mock("callee_tid", "RAX", 8),
            ObjectState::Dangling(Tid::new("free_tid")),
        );
        let pi_state = PiState::new(&Variable::mock("RSP", 8), Tid::new("call"));
        let id_replacement_map = BTreeMap::from([(
            AbstractIdentifier::mock("callee_tid", "RAX", 8),
            Data::from_target(
                AbstractIdentifier::mock("caller_tid", "RBX", 8),
                Bitvector::from_i64(42).into(),
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
