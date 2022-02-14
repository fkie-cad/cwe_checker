//! Methods of [`State`] for manipulating abstract IDs.

use super::*;
use crate::analysis::pointer_inference::object::AbstractObject;

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
            let caller_object = self.memory.get_object_mut(caller_id).unwrap();
            caller_object.overwrite_with(&param_object, offset);
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
}
