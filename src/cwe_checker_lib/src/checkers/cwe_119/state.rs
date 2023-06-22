use super::context::BoundsMetadata;
use super::Context;
use super::Data;
use crate::abstract_domain::*;
use crate::analysis::function_signature::FunctionSignature;
use crate::intermediate_representation::Project;
use crate::prelude::*;
use std::collections::BTreeMap;

/// The state consists of the abstract identifier for the current stack frame
/// and lists of the lower and upper bounds for all known memory objects.
///
/// The bounds of memory objects are computed the first time an access to it is observed.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// The abstract identifier of the stack frame of the function that the state belongs to.
    stack_id: AbstractIdentifier,
    /// The lower bounds of all memory objects for which accesses have been observed.
    object_lower_bounds: DomainMap<AbstractIdentifier, BitvectorDomain, UnionMergeStrategy>,
    /// The upper bounds of all memory objects for which accesses have been observed.
    object_upper_bounds: DomainMap<AbstractIdentifier, BitvectorDomain, UnionMergeStrategy>,
}

impl State {
    /// Create a new state representing the state at the start of the function
    /// given by the `function_tid` and corresponding function signature.
    ///
    /// Only the bounds of the current stack frame are known in this state,
    /// since there are no memory accesses to observe prior to the function start.
    pub fn new(function_tid: &Tid, function_sig: &FunctionSignature, project: &Project) -> State {
        let stack_id =
            AbstractIdentifier::from_var(function_tid.clone(), &project.stack_pointer_register);
        let stack_upper_bound: i64 = match project.stack_pointer_register.name.as_str() {
            "ESP" => 4,
            "RSP" => 8,
            _ => 0,
        };
        let stack_upper_bound = std::cmp::max(
            stack_upper_bound,
            function_sig.get_stack_params_total_size(),
        );
        let object_lower_bounds = BTreeMap::from([(
            stack_id.clone(),
            BitvectorDomain::new_top(stack_id.bytesize()),
        )]);
        let object_upper_bounds = BTreeMap::from([(
            stack_id.clone(),
            Bitvector::from_i64(stack_upper_bound)
                .into_resize_signed(stack_id.bytesize())
                .into(),
        )]);
        State {
            stack_id,
            object_lower_bounds: object_lower_bounds.into(),
            object_upper_bounds: object_upper_bounds.into(),
        }
    }

    /// Check for the given address whether the access to it would be in the boundaries for all possible target memory objects.
    /// Return a list of logging messages describing those cases
    /// where the access may fall outside of the corresponding memory object boundaries.
    pub fn check_address_access(
        &mut self,
        address: &Data,
        value_size: ByteSize,
        context: &Context,
    ) -> Vec<String> {
        let mut out_of_bounds_access_warnings = Vec::new();
        for (id, offset) in address.get_relative_values() {
            if !self.object_lower_bounds.contains_key(id) {
                self.compute_bounds_of_id(id, context);
            }
            if let Ok((lower_offset, upper_offset)) = offset.try_to_offset_interval() {
                if let Ok(lower_bound) = self.object_lower_bounds.get(id).unwrap().try_to_offset() {
                    if lower_bound > lower_offset {
                        out_of_bounds_access_warnings.push(format!("For the object ID {id} access to the offset {lower_offset} may be smaller than the lower object bound of {lower_bound}."));
                        if let (
                            Some(BoundsMetadata {
                                source: Some(source),
                                ..
                            }),
                            _,
                        ) = context.compute_bounds_of_id(id, &self.stack_id)
                        {
                            out_of_bounds_access_warnings.push(format!("The object bound is based on the possible source value {:#} for the object ID.", source.to_json_compact()));
                            let call_sequence_tids = collect_tids_for_cwe_warning(
                                source.get_if_unique_target().unwrap().0,
                                self,
                                context,
                            );
                            out_of_bounds_access_warnings
                                .push(format!("Relevant callgraph TIDs: [{call_sequence_tids}]"));
                        } else {
                            let mut callgraph_tids = format!("{}", self.stack_id.get_tid());
                            for call_tid in id.get_path_hints() {
                                callgraph_tids += &format!(", {call_tid}");
                            }
                            out_of_bounds_access_warnings
                                .push(format!("Relevant callgraph TIDs: [{callgraph_tids}]",));
                        }
                        // Replace the bound with `Top` to prevent duplicate CWE warnings with the same root cause.
                        self.object_lower_bounds
                            .insert(id.clone(), BitvectorDomain::new_top(address.bytesize()));
                    }
                }
                if let Ok(upper_bound) = self.object_upper_bounds.get(id).unwrap().try_to_offset() {
                    if upper_bound < upper_offset + (u64::from(value_size) as i64) {
                        out_of_bounds_access_warnings.push(format!("For the object ID {} access to the offset {} (size {}) may overflow the upper object bound of {}.",
                            id,
                            upper_offset,
                            u64::from(value_size),
                            upper_bound,
                        ));
                        if let (
                            _,
                            Some(BoundsMetadata {
                                source: Some(source),
                                ..
                            }),
                        ) = context.compute_bounds_of_id(id, &self.stack_id)
                        {
                            out_of_bounds_access_warnings.push(format!("The object bound is based on the possible source value {:#} for the object ID.", source.to_json_compact()));
                            let call_sequence_tids = collect_tids_for_cwe_warning(
                                source.get_if_unique_target().unwrap().0,
                                self,
                                context,
                            );
                            out_of_bounds_access_warnings
                                .push(format!("Relevant callgraph TIDs: [{call_sequence_tids}]"));
                        } else {
                            let mut callgraph_tids = format!("{}", self.stack_id.get_tid());
                            for call_tid in id.get_path_hints() {
                                callgraph_tids += &format!(", {call_tid}");
                            }
                            out_of_bounds_access_warnings
                                .push(format!("Relevant callgraph TIDs: [{callgraph_tids}]",));
                        }
                        // Replace the bound with `Top` to prevent duplicate CWE warnings with the same root cause.
                        self.object_upper_bounds
                            .insert(id.clone(), BitvectorDomain::new_top(address.bytesize()));
                    }
                }
            }
        }

        out_of_bounds_access_warnings
    }

    /// Compute the bounds of a memory object given by the provided `object_id`
    /// and insert the results into `self.object_lower_bounds` and `self.object_upper_bounds`.
    ///
    /// This function assumes that the objects bounds have not been computed prior to this function call.
    /// For bounds that could not be determined (e.g. because the source for the object ID is unknown)
    /// we insert `Top` bounds into the bounds maps.
    fn compute_bounds_of_id(&mut self, object_id: &AbstractIdentifier, context: &Context) {
        let (lower_bound, upper_bound) = context.compute_bounds_of_id(object_id, &self.stack_id);
        let lower_bound = match lower_bound {
            Some(bound_metadata) => Bitvector::from_i64(bound_metadata.resulting_bound)
                .into_resize_signed(object_id.bytesize())
                .into(),
            None => BitvectorDomain::new_top(object_id.bytesize()),
        };
        let upper_bound = match upper_bound {
            Some(bound_metadata) => Bitvector::from_i64(bound_metadata.resulting_bound)
                .into_resize_signed(object_id.bytesize())
                .into(),
            None => BitvectorDomain::new_top(object_id.bytesize()),
        };
        self.object_lower_bounds
            .insert(object_id.clone(), lower_bound);
        self.object_upper_bounds
            .insert(object_id.clone(), upper_bound);
    }
}

impl AbstractDomain for State {
    /// Merge two states by merging the known object bounds of both.
    fn merge(&self, other: &State) -> State {
        State {
            stack_id: self.stack_id.clone(),
            object_lower_bounds: self.object_lower_bounds.merge(&other.object_lower_bounds),
            object_upper_bounds: self.object_upper_bounds.merge(&other.object_upper_bounds),
        }
    }

    /// The state has no logical `Top` element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    #[allow(dead_code)]
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut state_map = Map::new();
        state_map.insert(
            "stack_id".to_string(),
            Value::String(self.stack_id.to_string()),
        );

        let lower_bounds: Vec<_> = self
            .object_lower_bounds
            .iter()
            .map(|(id, bound)| Value::String(format!("{id}: {bound}")))
            .collect();
        state_map.insert("lower_bounds".to_string(), Value::Array(lower_bounds));
        let upper_bounds: Vec<_> = self
            .object_upper_bounds
            .iter()
            .map(|(id, bound)| Value::String(format!("{id}: {bound}")))
            .collect();
        state_map.insert("upper_bounds".to_string(), Value::Array(upper_bounds));

        Value::Object(state_map)
    }
}

/// Collect all relevant call sequence TIDs corresponding to a CWE warning.
/// This includes:
/// - The TID of a root function from which both the allocation site and the site of the CWE warning can be reached
/// - All call TID that are relevant for reaching the allocation site from the root function.
/// - All call TIDs that are relevant for reachting the site of the CWE warning.
///   This list is complete in the sense that all possible paths in the call graph from the root function to the CWE warning site
///   are covered by these calls.
///
/// The resulting list is returned as a string,
/// as it is currently only used for human-readable context information in the CWE warnings.
fn collect_tids_for_cwe_warning(
    id: &AbstractIdentifier,
    state: &State,
    context: &Context,
) -> String {
    use crate::analysis::callgraph::find_call_sequences_to_target;
    let caller_tid = if context.project.program.term.subs.contains_key(id.get_tid()) {
        // The ID is the stack ID of some function.
        id.get_tid().clone()
    } else {
        // The ID corresponds to a malloc-like call
        let root_call_tid = if let Some(root_call) = id.get_path_hints().last() {
            root_call
        } else {
            id.get_tid()
        };
        context
            .project
            .program
            .term
            .find_sub_containing_jump(root_call_tid)
            .expect("Caller corresponding to call does not exist.")
    };
    let mut tids = Vec::new();
    tids.push(caller_tid.clone());
    tids.extend(id.get_path_hints().iter().cloned());
    if caller_tid != *state.stack_id.get_tid() {
        // We also need the possible call sequences from the caller to the current function
        let call_sequence_tids = find_call_sequences_to_target(
            &context.callgraph,
            &caller_tid,
            state.stack_id.get_tid(),
        );
        tids.extend(call_sequence_tids.into_iter());
    }
    // Build a string out of the TID list
    tids.iter()
        .map(|tid| format!("{tid}"))
        .reduce(|accum, elem| format!("{accum}, {elem}"))
        .unwrap()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{intermediate_representation::*, variable};

    #[test]
    fn test_new() {
        let context = Context::mock_x64();
        let state = State::new(
            &Tid::new("func"),
            &FunctionSignature::mock_x64(),
            context.project,
        );
        let stack_id = AbstractIdentifier::from_var(Tid::new("func"), &variable!("RSP:8"));

        assert_eq!(state.stack_id, stack_id);
        assert_eq!(state.object_lower_bounds.len(), 1);
        assert_eq!(state.object_upper_bounds.len(), 1);
        assert_eq!(
            *state.object_lower_bounds.get(&stack_id).unwrap(),
            BitvectorDomain::new_top(ByteSize::new(8))
        );
        assert_eq!(
            *state.object_upper_bounds.get(&stack_id).unwrap(),
            Bitvector::from_i64(8).into()
        );
    }

    #[test]
    fn test_check_address_access() {
        let context = Context::mock_x64();
        let mut state = State::new(
            &Tid::new("func"),
            &FunctionSignature::mock_x64(),
            context.project,
        );
        let stack_id = AbstractIdentifier::from_var(Tid::new("func"), &variable!("RSP:8"));
        // access in bounds
        let address = Data::from_target(stack_id.clone(), Bitvector::from_i64(-12).into());
        assert!(state
            .check_address_access(&address, ByteSize::new(8), &context)
            .is_empty());
        // access out of bounds
        let address = Data::from_target(stack_id.clone(), Bitvector::from_i64(4).into());
        assert_eq!(
            state
                .check_address_access(&address, ByteSize::new(8), &context)
                .len(),
            2
        );
        // subsequent errors are suppressed
        let address = Data::from_target(stack_id, Bitvector::from_i64(8).into());
        assert!(state
            .check_address_access(&address, ByteSize::new(8), &context)
            .is_empty());
    }

    #[test]
    fn test_compute_bounds_of_id() {
        let mut context = Context::mock_x64();
        context
            .malloc_tid_to_object_size_map
            .insert(Tid::new("malloc_call"), Data::from(Bitvector::from_i64(42)));
        context
            .call_to_caller_fn_map
            .insert(Tid::new("malloc_call"), Tid::new("main"));
        let mut state = State::new(
            &Tid::new("func"),
            &FunctionSignature::mock_x64(),
            context.project,
        );

        state.compute_bounds_of_id(&AbstractIdentifier::mock("malloc_call", "RAX", 8), &context);
        assert_eq!(state.object_lower_bounds.len(), 2);
        assert_eq!(
            state.object_lower_bounds[&AbstractIdentifier::mock("malloc_call", "RAX", 8)],
            Bitvector::from_i64(0).into()
        );
        assert_eq!(
            state.object_upper_bounds[&AbstractIdentifier::mock("malloc_call", "RAX", 8)],
            Bitvector::from_i64(42).into()
        );
    }
}
