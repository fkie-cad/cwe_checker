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
                        out_of_bounds_access_warnings.push(format!("For the object ID {} access to the offset {} may be smaller than the lower object bound of {}.",
                            id,
                            lower_offset,
                            lower_bound,
                        ));
                        // Replace the bound with `Top` to prevent duplicate CWE warnings with the same root cause.
                        self.object_lower_bounds
                            .insert(id.clone(), BitvectorDomain::new_top(address.bytesize()));
                    }
                }
                if let Ok(upper_bound) = self.object_upper_bounds.get(id).unwrap().try_to_offset() {
                    if upper_bound < upper_offset + (u64::from(value_size) as i64) {
                        out_of_bounds_access_warnings.push(format!("For the object ID {} access to the offset {} may be larger than the upper object bound of {}.",
                            id,
                            upper_offset + (u64::from(value_size) as i64),
                            upper_bound,
                        ));
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
        if context
            .malloc_tid_to_object_size_map
            .contains_key(object_id.get_tid())
        {
            let object_size = context.compute_size_of_heap_object(object_id);
            self.object_lower_bounds.insert(
                object_id.clone(),
                Bitvector::zero(object_id.bytesize().into()).into(),
            );
            self.object_upper_bounds
                .insert(object_id.clone(), object_size);
        } else if *object_id == self.stack_id {
            panic!("Current stack frame bounds not set.");
        } else if object_id.get_tid() == self.stack_id.get_tid()
            && object_id.get_path_hints().is_empty()
        {
            // Handle parameter IDs
            self.compute_bounds_of_param_id(object_id, context);
        } else {
            // The type of object is unknown, thus the size restrictions are also unknown.
            self.object_lower_bounds.insert(
                object_id.clone(),
                BitvectorDomain::new_top(object_id.bytesize()),
            );
            self.object_upper_bounds.insert(
                object_id.clone(),
                BitvectorDomain::new_top(object_id.bytesize()),
            );
        }
    }

    /// Compute the bounds of the memory object associated with the given parameter ID
    /// and add the results to the known object bounds of `self`.
    ///
    /// Since the memory object associated to a parameter may not be unique
    /// the bounds are only approximated from those objects where exact bounds could be determined.
    /// If different objects were found the bounds are approximated by the strictest bounds that were found.
    fn compute_bounds_of_param_id(
        &mut self,
        param_object_id: &AbstractIdentifier,
        context: &Context,
    ) {
        let object_data = context.recursively_substitute_param_values(&DataDomain::from_target(
            param_object_id.clone(),
            Bitvector::zero(param_object_id.bytesize().into()).into(),
        ));
        let mut lower_bound = None;
        let mut upper_bound = None;

        for (id, offset) in object_data.get_relative_values() {
            // Right now we ignore cases where we do not know the exact offset into the object.
            let offset = match offset.try_to_offset() {
                Ok(offset) => offset,
                Err(_) => continue,
            };
            if context
                .malloc_tid_to_object_size_map
                .contains_key(id.get_tid())
            {
                let object_size = context.compute_size_of_heap_object(id);
                lower_bound = lower_bound
                    .map(|old_bound| std::cmp::max(old_bound, -offset))
                    .or(Some(-offset));
                if let Ok(concrete_object_size) = object_size.try_to_offset() {
                    upper_bound = upper_bound
                        .map(|old_bound| std::cmp::min(old_bound, concrete_object_size - offset))
                        .or(Some(concrete_object_size - offset));
                }
            } else if context.is_stack_frame_id(id) {
                let stack_frame_upper_bound = context
                    .function_signatures
                    .get(id.get_tid())
                    .unwrap()
                    .get_stack_params_total_size();
                upper_bound = upper_bound
                    .map(|old_bound| std::cmp::min(old_bound, stack_frame_upper_bound))
                    .or(Some(stack_frame_upper_bound));
                // We do not set a lower bound since we do not know the concrete call site for stack pointers,
                // which we would need to determine a correct lower bound.
            }
            // FIXME: Cases not handled here include unresolved parameter IDs, unknown IDs and global pointers.
            // For the first two we do not have any size information.
            // For global pointers we need some kind of pre-analysis so that we do not have to assume
            // that the pointer may address the complete range of global data addresses.
        }
        let lower_bound = match lower_bound {
            Some(bound) => Bitvector::from_i64(bound)
                .into_resize_signed(param_object_id.bytesize())
                .into(),
            None => BitvectorDomain::new_top(param_object_id.bytesize()),
        };
        let upper_bound = match upper_bound {
            Some(bound) => Bitvector::from_i64(bound)
                .into_resize_signed(param_object_id.bytesize())
                .into(),
            None => BitvectorDomain::new_top(param_object_id.bytesize()),
        };
        self.object_lower_bounds
            .insert(param_object_id.clone(), lower_bound);
        self.object_upper_bounds
            .insert(param_object_id.clone(), upper_bound);
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::intermediate_representation::Variable;

    #[test]
    fn test_new() {
        let context = Context::mock_x64();
        let state = State::new(
            &Tid::new("func"),
            &FunctionSignature::mock_x64(),
            context.project,
        );
        let stack_id = AbstractIdentifier::from_var(Tid::new("func"), &Variable::mock("RSP", 8));

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
        let stack_id = AbstractIdentifier::from_var(Tid::new("func"), &Variable::mock("RSP", 8));
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
            1
        );
        // subsequent errors are suppressed
        let address = Data::from_target(stack_id, Bitvector::from_i64(8).into());
        assert!(state
            .check_address_access(&address, ByteSize::new(8), &context)
            .is_empty());
    }

    #[test]
    fn test_compute_bounds_of_id() {
        todo!()
    }

    #[test]
    fn test_compute_bounds_of_param_id() {
        todo!()
    }
}
