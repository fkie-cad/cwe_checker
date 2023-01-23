use super::Context;
use crate::abstract_domain::{AbstractIdentifier, DataDomain, IntervalDomain, TryToBitvec};
use crate::prelude::*;

/// This struct contains the computed bound for an object.
/// If the object is a parameter object,
/// it also contains metadata about the source object used to determine the bound for the parameter object.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BoundsMetadata {
    /// The source object (and the offset into the source object that the object points to)
    /// if the bound of the memory object is derived from another object (e.g. for parameter objects).
    pub source: Option<DataDomain<IntervalDomain>>,
    /// The resulting bound for the memory object.
    pub resulting_bound: i64,
}

impl BoundsMetadata {
    /// Create a new instance without source metadata.
    pub fn new(resulting_bound: i64) -> BoundsMetadata {
        BoundsMetadata {
            source: None,
            resulting_bound,
        }
    }

    /// Create an instance where the source of the bound is given by `id + offset`.
    pub fn from_source(
        id: &AbstractIdentifier,
        offset: &IntervalDomain,
        resulting_bound: i64,
    ) -> BoundsMetadata {
        BoundsMetadata {
            source: Some(DataDomain::from_target(id.clone(), offset.clone())),
            resulting_bound,
        }
    }
}

/// If `bound` is `None`, replace it with `new_bound`.
/// Else only replace it if the bound in `new_bound` is smaller than the existing bound.
fn replace_if_smaller_bound(bound: &mut Option<BoundsMetadata>, new_bound: BoundsMetadata) {
    if let Some(old_bound) = bound {
        if old_bound.resulting_bound > new_bound.resulting_bound {
            *bound = Some(new_bound);
        }
    } else {
        *bound = Some(new_bound);
    }
}

/// If `bound` is `None`, replace it with `new_bound`.
/// Else only replace it if the bound in `new_bound` is larger than the existing bound.
fn replace_if_larger_bound(bound: &mut Option<BoundsMetadata>, new_bound: BoundsMetadata) {
    if let Some(old_bound) = bound {
        if old_bound.resulting_bound < new_bound.resulting_bound {
            *bound = Some(new_bound);
        }
    } else {
        *bound = Some(new_bound);
    }
}

impl<'a> Context<'a> {
    /// Compute the bounds of the memory object associated with the given parameter ID.
    ///
    /// Since the memory object associated to a parameter may not be unique
    /// the bounds are only approximated from those objects where exact bounds could be determined.
    /// If different objects were found the bounds are approximated by the strictest bounds that were found.
    fn compute_bounds_of_param_id(
        &self,
        param_object_id: &AbstractIdentifier,
    ) -> (Option<BoundsMetadata>, Option<BoundsMetadata>) {
        let object_data = self.recursively_substitute_param_values(&DataDomain::from_target(
            param_object_id.clone(),
            Bitvector::zero(param_object_id.bytesize().into()).into(),
        ));
        let mut lower_bound: Option<BoundsMetadata> = None;
        let mut upper_bound: Option<BoundsMetadata> = None;

        for (id, offset) in object_data.get_relative_values() {
            // Right now we ignore cases where we do not know the exact offset into the object.
            let concrete_offset = match offset.try_to_offset() {
                Ok(offset) => offset,
                Err(_) => continue,
            };
            if self
                .malloc_tid_to_object_size_map
                .contains_key(id.get_tid())
            {
                replace_if_larger_bound(
                    &mut lower_bound,
                    BoundsMetadata::from_source(id, offset, -concrete_offset),
                );
                let object_size = self.compute_size_of_heap_object(id);
                if let Ok(concrete_object_size) = object_size.try_to_offset() {
                    replace_if_smaller_bound(
                        &mut upper_bound,
                        BoundsMetadata::from_source(
                            id,
                            offset,
                            concrete_object_size - concrete_offset,
                        ),
                    );
                }
            } else if self.is_stack_frame_id(id) {
                let stack_frame_upper_bound = self
                    .function_signatures
                    .get(id.get_tid())
                    .unwrap()
                    .get_stack_params_total_size();
                replace_if_smaller_bound(
                    &mut upper_bound,
                    BoundsMetadata::from_source(
                        id,
                        offset,
                        stack_frame_upper_bound - concrete_offset,
                    ),
                );
                // We do not set a lower bound since we do not know the concrete call site for stack pointers,
                // which we would need to determine a correct lower bound.
            }
            // FIXME: Cases not handled here include unresolved parameter IDs, unknown IDs and global pointers.
            // For the first two we do not have any size information.
            // For global pointers we need some kind of pre-analysis so that we do not have to assume
            // that the pointer may address the complete range of global data addresses.
        }
        (lower_bound, upper_bound)
    }

    /// Compute the bounds of a memory object given by the provided `object_id`.
    ///
    /// Returns `(lower_bound, upper_bound)`, where the bounds may be `None` if they could not be determined.
    pub fn compute_bounds_of_id(
        &self,
        object_id: &AbstractIdentifier,
        current_stack_frame_id: &AbstractIdentifier,
    ) -> (Option<BoundsMetadata>, Option<BoundsMetadata>) {
        if self
            .malloc_tid_to_object_size_map
            .contains_key(object_id.get_tid())
        {
            let object_size = self.compute_size_of_heap_object(object_id);
            if let Ok(object_size) = object_size.try_to_offset() {
                (
                    Some(BoundsMetadata::new(0)),
                    Some(BoundsMetadata::new(object_size)),
                )
            } else {
                (Some(BoundsMetadata::new(0)), None)
            }
        } else if object_id == current_stack_frame_id {
            let stack_frame_upper_bound = self
                .function_signatures
                .get(object_id.get_tid())
                .unwrap()
                .get_stack_params_total_size();
            (None, Some(BoundsMetadata::new(stack_frame_upper_bound)))
        } else if object_id.get_tid() == current_stack_frame_id.get_tid()
            && object_id.get_path_hints().is_empty()
        {
            // Handle parameter IDs
            self.compute_bounds_of_param_id(object_id)
        } else {
            // The type of object is unknown, thus the size restrictions are also unknown.
            (None, None)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::analysis::pointer_inference::Data;
    use crate::{bitvec, intermediate_representation::parsing};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_compute_bounds_of_param_id() {
        let mut context = Context::mock_x64();
        let param_id = AbstractIdentifier::mock("func", "RDI", 8);
        let param_id_2 = AbstractIdentifier::mock("func", "RSI", 8);
        let callsite_id = AbstractIdentifier::mock("callsite_id", "RDI", 8);
        let callsite_id_2 = AbstractIdentifier::mock("callsite_id", "RSI", 8);
        let malloc_call_id = AbstractIdentifier::mock("malloc_call", "RAX", 8);
        let main_stack_id = AbstractIdentifier::mock("main", "RSP", 8);

        let param_value = Data::from_target(malloc_call_id.clone(), bitvec!("2:8").into());
        let param_value_2 = Data::from_target(main_stack_id.clone(), bitvec!("-10:8").into());
        let param_replacement_map = HashMap::from([
            (callsite_id, param_value.clone()),
            (callsite_id_2, param_value_2.clone()),
        ]);
        let callee_to_callsites_map =
            HashMap::from([(Tid::new("func"), HashSet::from([Tid::new("callsite_id")]))]);
        context.param_replacement_map = param_replacement_map;
        context.callee_to_callsites_map = callee_to_callsites_map;
        context
            .malloc_tid_to_object_size_map
            .insert(Tid::new("malloc_call"), Data::from(bitvec!("42:8")));
        context.call_to_caller_fn_map = HashMap::from([
            (Tid::new("malloc_call"), Tid::new("main")),
            (Tid::new("callsite_id"), Tid::new("main")),
        ]);
        // Test bound computation if the param gets resolved to a heap object
        let (lower_bound, upper_bound) = context.compute_bounds_of_param_id(&param_id);
        assert_eq!(lower_bound.unwrap().resulting_bound, -2);
        assert_eq!(upper_bound.unwrap().resulting_bound, 40);
        // Test bound computation if the param gets resolved to a caller stack frame
        let (lower_bound, upper_bound) = context.compute_bounds_of_param_id(&param_id_2);
        assert_eq!(lower_bound, None);
        assert_eq!(upper_bound.unwrap().resulting_bound, 10);
    }
}
