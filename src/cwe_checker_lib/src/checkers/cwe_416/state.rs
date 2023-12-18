use crate::analysis::pointer_inference::State as PiState;
use crate::{
    abstract_domain::{AbstractDomain, AbstractIdentifier, DomainMap, UnionMergeStrategy},
    analysis::pointer_inference::Data,
    prelude::*,
};
use std::collections::{BTreeMap, BTreeSet};

/// The state of a memory object for which at least one possible call to a `free`-like function was detected.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
enum ObjectState {
    /// The object is already freed, i.e. pointers to it are dangling.
    /// The associated TIDs denote the point in time when the object was freed
    /// and possibly the call path taken to that point in time.
    Dangling(Vec<Tid>),
    /// The object is already freed and a use-after-free CWE message for it was already generated.
    /// This object state is used to prevent duplicate CWE warnings with the same root cause.
    /// It still holds a path to a point in time where the object was freed.
    AlreadyFlagged(Vec<Tid>),
}

impl AbstractDomain for ObjectState {
    /// Merge two object states.
    /// If both object states are identical then use the shorter path to `free` in the result.
    fn merge(&self, other: &Self) -> Self {
        use std::cmp::Ordering;

        match (self, other) {
            (
                ObjectState::AlreadyFlagged(free_path),
                ObjectState::AlreadyFlagged(other_free_path),
            ) => {
                let shortest_path = match free_path.len().cmp(&other_free_path.len()) {
                    Ordering::Less => free_path.clone(),
                    Ordering::Equal => std::cmp::min(free_path, other_free_path).clone(),
                    Ordering::Greater => other_free_path.clone(),
                };
                ObjectState::AlreadyFlagged(shortest_path)
            }
            (ObjectState::AlreadyFlagged(free_path), _)
            | (_, ObjectState::AlreadyFlagged(free_path)) => {
                ObjectState::AlreadyFlagged(free_path.clone())
            }
            (ObjectState::Dangling(free_path), ObjectState::Dangling(other_free_path)) => {
                let shortest_path = match free_path.len().cmp(&other_free_path.len()) {
                    Ordering::Less => free_path.clone(),
                    Ordering::Equal => std::cmp::min(free_path, other_free_path).clone(),
                    Ordering::Greater => other_free_path.clone(),
                };
                ObjectState::Dangling(shortest_path)
            }
        }
    }

    /// The `Top` element for object states is a dangling pointer.
    fn is_top(&self) -> bool {
        matches!(self, ObjectState::Dangling(_))
    }
}

/// The `State` keeps track of the list of abstract IDs of memory objects that may have been freed already
/// together with the corresponding object states.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// The TID of the current function.
    pub current_fn_tid: Tid,
    /// Map from the abstract ID of dangling objects to their object state.
    dangling_objects: DomainMap<AbstractIdentifier, ObjectState, UnionMergeStrategy>,
    /// Memory objects that were generated and freed in the same call are tracked in a separate map.
    /// Such objects are often analysis errors.
    /// Tracking them separately prevents them from masking genuine Use-After-Free cases in the caller.
    dangling_objects_generated_and_freed_in_same_call:
        DomainMap<AbstractIdentifier, ObjectState, UnionMergeStrategy>,
}

impl State {
    /// Create a new, empty state, i.e. a state without any object marked as already freed.
    pub fn new(current_fn_tid: Tid) -> State {
        State {
            current_fn_tid,
            dangling_objects: BTreeMap::new().into(),
            dangling_objects_generated_and_freed_in_same_call: BTreeMap::new().into(),
        }
    }

    /// Check the given address on whether it may point to already freed memory.
    /// For each possible dangling pointer target the abstract ID of the object
    /// and the path to the corresponding site where the object was freed is returned.
    /// The object states of corresponding memory objects are set to [`ObjectState::AlreadyFlagged`]
    /// to prevent reporting duplicate CWE messages with the same root cause.
    pub fn check_address_for_use_after_free(
        &mut self,
        address: &Data,
    ) -> Option<Vec<(AbstractIdentifier, Vec<Tid>)>> {
        let mut free_ids_of_dangling_pointers = Vec::new();
        for id in address.get_relative_values().keys() {
            if let Some(ObjectState::Dangling(free_id_path)) = self.dangling_objects.get(id) {
                let free_id_path = free_id_path.clone();
                free_ids_of_dangling_pointers.push((id.clone(), free_id_path.clone()));

                self.dangling_objects
                    .insert(id.clone(), ObjectState::AlreadyFlagged(free_id_path));
            }
            if let Some(ObjectState::Dangling(free_id_path)) = self
                .dangling_objects_generated_and_freed_in_same_call
                .get(id)
            {
                let free_id_path = free_id_path.clone();
                free_ids_of_dangling_pointers.push((id.clone(), free_id_path.clone()));

                self.dangling_objects_generated_and_freed_in_same_call
                    .insert(id.clone(), ObjectState::AlreadyFlagged(free_id_path));
            }
        }
        if free_ids_of_dangling_pointers.is_empty() {
            None
        } else {
            Some(free_ids_of_dangling_pointers)
        }
    }

    /// Mark the given object ID as freed with the given `free_id_path` denoting the path to the site where it is freed.
    ///
    /// If the object ID was already marked as dangling,
    /// return it plus the (previously saved) path to the site where it was freed.
    #[must_use]
    fn mark_as_freed(
        &mut self,
        object_id: &AbstractIdentifier,
        free_id_path: Vec<Tid>,
        pi_state: &PiState,
    ) -> Option<(AbstractIdentifier, Vec<Tid>)> {
        if pi_state.memory.is_unique_object(object_id).ok() == Some(false) {
            // FIXME: We cannot distinguish different objects represented by the same ID.
            // So to avoid producing lots of false positive warnings
            // we ignore these cases by not marking these IDs as freed.
            return None;
        }
        if object_id.get_path_hints().last() == free_id_path.last() {
            // The object was created in the same call as it is now freed.
            if let Some(ObjectState::Dangling(old_free_id_path)) = self
                .dangling_objects_generated_and_freed_in_same_call
                .insert(
                    object_id.clone(),
                    ObjectState::Dangling(free_id_path.clone()),
                )
            {
                return Some((object_id.clone(), old_free_id_path.clone()));
            }
        } else if let Some(ObjectState::Dangling(old_free_id_path)) = self.dangling_objects.insert(
            object_id.clone(),
            ObjectState::Dangling(free_id_path.clone()),
        ) {
            return Some((object_id.clone(), old_free_id_path.clone()));
        }

        None
    }

    /// All TIDs that the given `param` may point to are marked as freed, i.e. pointers to them are dangling.
    /// For each ID that was already marked as dangling return a string describing the root cause of a possible double free bug.
    ///
    /// The function heuristically detects IDs related to recursive data structures (e.g. linked lists).
    /// Such IDs are ignored when marking objects as freed.
    pub fn handle_param_of_free_call(
        &mut self,
        call_tid: &Tid,
        param: &Data,
        pi_state: &PiState,
    ) -> Option<Vec<(AbstractIdentifier, Vec<Tid>)>> {
        // FIXME: This function could also generate debug log messages whenever nonsensical information is detected.
        // E.g. stack frame IDs or non-zero ID offsets can be indicators of other bugs.
        let mut warnings = Vec::new();
        let generic_pointer_size = pi_state.stack_id.bytesize();
        // Heuristically ignore recursive IDs
        for id in get_non_recursive_ids(param, generic_pointer_size) {
            if let Some(warning_data) = self.mark_as_freed(id, vec![call_tid.clone()], pi_state) {
                warnings.push(warning_data);
            }
        }
        if !warnings.is_empty() {
            Some(warnings)
        } else {
            None
        }
    }

    /// Add objects that were freed in the callee of a function call to the list of dangling pointers of `self`.
    /// Note that this function does not check for double frees.
    ///
    /// The function heuristically detects when parameter values contain IDs
    /// corresponding to recursive data structures (e.g. linked lists).
    /// Such IDs are ignored, i.e. their object status is not transferred from the callee.
    pub fn collect_freed_objects_from_called_function(
        &mut self,
        state_before_return: &State,
        id_replacement_map: &BTreeMap<AbstractIdentifier, Data>,
        call_tid: &Tid,
        pi_state: &PiState,
    ) {
        let generic_pointer_size = pi_state.stack_id.bytesize();
        let call_tid_with_suffix = call_tid.clone().with_id_suffix("_param");

        for (callee_id, callee_object_state) in state_before_return.dangling_objects.iter() {
            if let Some(caller_value) = id_replacement_map.get(callee_id) {
                // Heuristically filter out recursive IDs
                for caller_id in get_non_recursive_ids(caller_value, generic_pointer_size) {
                    if caller_id.get_tid() == call_tid
                        || caller_id.get_tid() == &call_tid_with_suffix
                    {
                        // FIXME: We heuristically ignore free operations if they happen in the same call as the creation of the object.
                        // This reduces false positives, but also produces false negatives for some returned dangling pointers.
                        continue;
                    }

                    match callee_object_state {
                        ObjectState::Dangling(callee_free_path) => {
                            let mut free_id_path = callee_free_path.clone();
                            free_id_path.push(call_tid.clone());
                            let _ = self.mark_as_freed(caller_id, free_id_path, pi_state);
                        }
                        // FIXME: To reduce false positives and duplicates we heuristically assume
                        // that if an object is flagged in the callee
                        // then Use After Frees in the caller are duplicates from the flagged access in the callee.
                        // And that the corresponding dangling objects do not reach the caller in this case.
                        // Note that this heuristic will produce false negatives in some cases.
                        ObjectState::AlreadyFlagged(_) => (),
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
            dangling_objects_generated_and_freed_in_same_call: self
                .dangling_objects_generated_and_freed_in_same_call
                .merge(&other.dangling_objects_generated_and_freed_in_same_call),
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
        let format_vec = |vec| {
            let mut string = String::new();
            for elem in vec {
                string += &format!("{},", elem);
            }
            string
        };

        let mut state_map = Map::new();
        state_map.insert(
            "current_function".to_string(),
            Value::String(format!("{}", self.current_fn_tid)),
        );
        for (id, object_state) in self.dangling_objects.iter() {
            match object_state {
                ObjectState::Dangling(free_path) => state_map.insert(
                    format!("{id}"),
                    Value::String(format!("Dangling([{}])", format_vec(free_path))),
                ),
                ObjectState::AlreadyFlagged(free_path) => state_map.insert(
                    format!("{id}"),
                    Value::String(format!("Already flagged([{}])", format_vec(free_path))),
                ),
            };
        }
        for (id, object_state) in self
            .dangling_objects_generated_and_freed_in_same_call
            .iter()
        {
            match object_state {
                ObjectState::Dangling(free_path) => state_map.insert(
                    format!("{id} (already dangling in callee)"),
                    Value::String(format!("Dangling([{}])", format_vec(free_path))),
                ),
                ObjectState::AlreadyFlagged(free_path) => state_map.insert(
                    format!("{id} (already dangling in callee)"),
                    Value::String(format!("Already flagged([{}])", format_vec(free_path))),
                ),
            };
        }
        Value::Object(state_map)
    }
}

/// Return the set of relative IDs contained in the input `data` after filtering out recursive IDs.
///
/// An ID is *recursive*, i.e. assumed to correspond to a recursive data structure like a linked list,
/// if its parent abstract location is also contained as an ID in `data`
/// or if some ID contained in `data` has this ID as its parent.
fn get_non_recursive_ids(
    data: &Data,
    generic_pointer_size: ByteSize,
) -> BTreeSet<&AbstractIdentifier> {
    let ids: BTreeSet<_> = data.get_relative_values().keys().collect();
    let mut filtered_ids = ids.clone();
    for id in &ids {
        if let Some(parent_id) = id.get_id_with_parent_location(generic_pointer_size) {
            if ids.contains(&parent_id) {
                filtered_ids.remove(*id);
                filtered_ids.remove(&parent_id);
            }
        }
    }
    filtered_ids
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        abstract_domain::DataDomain, bitvec, intermediate_representation::parsing, variable,
    };
    use std::collections::BTreeSet;

    #[test]
    fn test_check_address_for_use_after_free() {
        let mut state = State::new(Tid::new("current_fn"));
        state.dangling_objects.insert(
            AbstractIdentifier::mock("obj_id", "RAX", 8),
            ObjectState::Dangling(vec![Tid::new("free_call")]),
        );
        state.dangling_objects.insert(
            AbstractIdentifier::mock("flagged_obj_id", "RAX", 8),
            ObjectState::AlreadyFlagged(vec![Tid::new("free_call")]),
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
            ObjectState::AlreadyFlagged(vec![Tid::new("free_call")])
        );
        assert_eq!(
            *state
                .dangling_objects
                .get(&AbstractIdentifier::mock("flagged_obj_id", "RAX", 8))
                .unwrap(),
            ObjectState::AlreadyFlagged(vec![Tid::new("free_call")])
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
            ObjectState::Dangling(vec![Tid::new("free_call")])
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
            ObjectState::Dangling(vec![Tid::new("free_tid")]),
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
            &ObjectState::Dangling(vec![Tid::new("free_tid"), Tid::new("call_tid")])
        );
    }

    #[test]
    fn test_filtering_of_recursive_ids() {
        let data = DataDomain::mock_from_target_map(BTreeMap::from([
            (
                AbstractIdentifier::mock_nested("time1", "r0:4", &[], 4),
                bitvec!("0x0:4").into(),
            ),
            (
                AbstractIdentifier::mock_nested("time1", "r0:4", &[0], 4),
                bitvec!("0x0:4").into(),
            ),
            (
                AbstractIdentifier::mock_nested("unique1", "r0:4", &[], 4),
                bitvec!("0x0:4").into(),
            ),
            (
                AbstractIdentifier::mock_nested("unique2", "r0:4", &[0], 4),
                bitvec!("0x0:4").into(),
            ),
        ]));
        let filtered_ids = get_non_recursive_ids(&data, ByteSize::new(4));
        assert_eq!(
            filtered_ids,
            BTreeSet::from([
                &AbstractIdentifier::mock_nested("unique1", "r0:4", &[], 4),
                &AbstractIdentifier::mock_nested("unique2", "r0:4", &[0], 4)
            ])
        );
    }
}
