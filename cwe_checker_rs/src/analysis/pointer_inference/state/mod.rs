use super::object_list::AbstractObjectList;
use super::Data;
use crate::abstract_domain::*;
use crate::bil::*;
use crate::prelude::*;
use crate::term::symbol::ExternSymbol;
use std::collections::{BTreeMap, BTreeSet};

mod access_handling;

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    register: BTreeMap<Variable, Data>,
    /// The list of all known memory objects.
    pub memory: AbstractObjectList,
    /// The abstract identifier of the current stack frame.
    /// It points to the to the base of the stack frame, i.e. only negative offsets point into the current stack frame.
    pub stack_id: AbstractIdentifier,
    /// All known IDs of caller stack frames.
    /// Note that these IDs are named after the callsite,
    /// i.e. we can distinguish every callsite and for recursive functions the caller and current stack frames have different IDs.
    ///
    /// Writes to the current stack frame with offset >= 0 are written to *all* caller stack frames.
    /// Reads to the current stack frame with offset >= 0 are handled as merge-read from all caller stack frames.
    pub caller_stack_ids: BTreeSet<AbstractIdentifier>,
    /// All IDs of objects that are known to some caller.
    /// This is an overapproximation of all object IDs that may have been passed as parameters to the function.
    /// The corresponding objects are not allowed to be deleted (even if no pointer to them exists anymore)
    /// so that after returning from a call the caller can recover their modified contents
    /// and the callee does not accidentally delete this information if it loses all pointers to an object.
    ///
    /// Note that IDs that the callee should not have access to are not included here.
    /// For these IDs the caller can assume that the contents of the corresponding memory object were not accessed or modified by the call.
    pub ids_known_to_caller: BTreeSet<AbstractIdentifier>,
}

impl State {
    /// Create a new state that contains only one memory object corresponding to the stack.
    /// The stack offset will be set to zero.
    pub fn new(stack_register: &Variable, function_tid: Tid) -> State {
        let stack_id = AbstractIdentifier::new(
            function_tid,
            AbstractLocation::from_var(stack_register).unwrap(),
        );
        let mut register: BTreeMap<Variable, Data> = BTreeMap::new();
        register.insert(
            stack_register.clone(),
            PointerDomain::new(
                stack_id.clone(),
                Bitvector::zero((stack_register.bitsize().unwrap() as usize).into()).into(),
            )
            .into(),
        );
        State {
            register,
            memory: AbstractObjectList::from_stack_id(
                stack_id.clone(),
                stack_register.bitsize().unwrap(),
            ),
            stack_id,
            caller_stack_ids: BTreeSet::new(),
            ids_known_to_caller: BTreeSet::new(),
        }
    }

    /// Clear all non-callee-saved registers from the state.
    /// This automatically also removes all virtual registers.
    /// The parameter is a list of callee-saved register names.
    pub fn clear_non_callee_saved_register(&mut self, callee_saved_register_names: &[String]) {
        let register = self
            .register
            .iter()
            .filter_map(|(register, value)| {
                if callee_saved_register_names
                    .iter()
                    .any(|reg_name| **reg_name == register.name)
                {
                    Some((register.clone(), value.clone()))
                } else {
                    None
                }
            })
            .collect();
        self.register = register;
    }

    /// Mark those parameter values of an extern function call, that are passed on the stack,
    /// as unknown data (since the function may modify them).
    pub fn clear_stack_parameter(&mut self, extern_call: &ExternSymbol) -> Result<(), Error> {
        let mut result_log = Ok(());
        for arg in &extern_call.arguments {
            match &arg.location {
                Expression::Var(_) => {}
                location_expression => {
                    let arg_size = arg
                        .var
                        .bitsize()
                        .expect("Encountered argument with unknown size");
                    let data_top = Data::new_top(arg_size);
                    if let Err(err) = self.write_to_address(location_expression, &data_top) {
                        result_log = Err(err);
                    }
                }
            }
        }
        // We only return the last error encountered.
        result_log
    }

    /// Replace all occurences of old_id with new_id and adjust offsets accordingly.
    /// This is needed to replace stack/caller IDs on call and return instructions.
    ///
    /// **Example:**
    /// Assume the old_id points to offset 0 in the corresponding memory object and the new_id points to offset -32.
    /// Then the offset_adjustment is -32.
    /// The offset_adjustment gets *added* to the base offset in self.memory.ids (so that it points to offset -32 in the memory object),
    /// while it gets *subtracted* from all pointer values (so that they still point to the same spot in the corresponding memory object).
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        for register_data in self.register.values_mut() {
            register_data.replace_abstract_id(old_id, new_id, &(-offset_adjustment.clone()));
        }
        self.memory
            .replace_abstract_id(old_id, new_id, offset_adjustment);
        if &self.stack_id == old_id {
            self.stack_id = new_id.clone();
        }
        if self.caller_stack_ids.get(old_id).is_some() {
            self.caller_stack_ids.remove(old_id);
            self.caller_stack_ids.insert(new_id.clone());
        }
        if self.ids_known_to_caller.get(old_id).is_some() {
            self.ids_known_to_caller.remove(old_id);
            self.ids_known_to_caller.insert(new_id.clone());
        }
    }

    /// Remove all objects that cannot longer be reached by any known pointer.
    /// This does not remove objects, where some caller may still know a pointer to the object.
    ///
    /// Right now it uses the conservative overapproximation of all possible pointer targets contained in a memory object,
    /// which will sometimes prevent memory objects from being removed
    /// even if no actual pointer to it can be reconstructed from the state.
    /// This may change in the future if memory consumption is too high (TODO: measure that).
    pub fn remove_unreferenced_objects(&mut self) {
        // get all referenced IDs
        let mut referenced_ids = BTreeSet::new();
        for (_reg_name, data) in self.register.iter() {
            referenced_ids.append(&mut data.referenced_ids());
        }
        referenced_ids.insert(self.stack_id.clone());
        referenced_ids.append(&mut self.caller_stack_ids.clone());
        referenced_ids.append(&mut self.ids_known_to_caller.clone());
        referenced_ids = self.add_recursively_referenced_ids_to_id_set(referenced_ids);
        // remove unreferenced IDs
        self.memory.remove_unused_ids(&referenced_ids);
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and all IDs contained in them to the set of IDs.
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
            let memory_ids = self.memory.get_referenced_ids(&id);
            for mem_id in memory_ids {
                if ids.get(mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Merge the callee stack with the caller stack.
    ///
    /// This deletes the pointer from the callee_id to the corresponding memory object
    /// and updates all other references pointing to the callee_id to point to the caller_id.
    /// The offset adjustment is handled as in `replace_abstract_id`.
    ///
    /// Note that right now the content of the callee memory object is *not* merged into the caller memory object.
    /// In general this is the correct behaviour
    /// as the content below the stack pointer should be considered uninitialized memory after returning to the caller.
    /// However, an aggressively optimizing compiler or an unknown calling convention may deviate from this.
    pub fn merge_callee_stack_to_caller_stack(
        &mut self,
        callee_id: &AbstractIdentifier,
        caller_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        self.memory.remove_object_pointer(callee_id);
        self.replace_abstract_id(callee_id, caller_id, offset_adjustment);
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    ///
    /// If this may cause double frees (i.e. the object in question may have been freed already),
    /// an error with the list of possibly already freed objects is returned.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &PointerDomain<BitvectorDomain>,
    ) -> Result<(), Vec<(AbstractIdentifier, Error)>> {
        self.memory.mark_mem_object_as_freed(object_pointer)
    }

    /// Remove all virtual register from the state.
    /// This should only be done in cases where it is known that no virtual registers can be alive.
    ///
    /// Example: At the start of a basic block no virtual registers should be alive.
    pub fn remove_virtual_register(&mut self) {
        self.register = self
            .register
            .clone()
            .into_iter()
            .filter(|(register, _value)| !register.is_temp)
            .collect();
    }

    /// Recursively remove all `caller_stack_ids` not corresponding to the given caller.
    pub fn remove_other_caller_stack_ids(&mut self, caller_id: &AbstractIdentifier) {
        let mut ids_to_remove = self.caller_stack_ids.clone();
        ids_to_remove.remove(caller_id);
        for register_value in self.register.values_mut() {
            register_value.remove_ids(&ids_to_remove);
        }
        self.memory.remove_ids(&ids_to_remove);
        self.caller_stack_ids = BTreeSet::new();
        self.caller_stack_ids.insert(caller_id.clone());
        self.ids_known_to_caller = self
            .ids_known_to_caller
            .difference(&ids_to_remove)
            .cloned()
            .collect();
    }

    /// Add those objects from the `caller_state` to `self`, that are not known to `self`.
    ///
    /// Since self does not know these objects, we assume that the current function could not have accessed
    /// them in any way during execution.
    /// This means they are unchanged from the moment of the call until the return from the call,
    /// thus we can simply copy their object-state from the moment of the call.
    pub fn readd_caller_objects(&mut self, caller_state: &State) {
        self.memory.append_unknown_objects(&caller_state.memory);
    }
}

impl AbstractDomain for State {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.stack_id, other.stack_id);
        let mut merged_register = BTreeMap::new();
        for (register, other_value) in other.register.iter() {
            if let Some(value) = self.register.get(register) {
                let merged_value = value.merge(other_value);
                if !merged_value.is_top() {
                    // We only have to keep non-*Top* elements.
                    merged_register.insert(register.clone(), merged_value);
                }
            }
        }
        let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: merged_register,
            memory: merged_memory_objects,
            stack_id: self.stack_id.clone(),
            caller_stack_ids: self
                .caller_stack_ids
                .union(&other.caller_stack_ids)
                .cloned()
                .collect(),
            ids_known_to_caller: self
                .ids_known_to_caller
                .union(&other.ids_known_to_caller)
                .cloned()
                .collect(),
        }
    }

    /// A state has no *Top* element
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a more compact json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut state_map = Map::new();
        let register = self
            .register
            .iter()
            .map(|(var, data)| (var.name.clone(), data.to_json_compact()))
            .collect();
        let register = Value::Object(register);
        state_map.insert("register".into(), register);
        state_map.insert("memory".into(), self.memory.to_json_compact());
        state_map.insert(
            "stack_id".into(),
            Value::String(format!("{}", self.stack_id)),
        );
        state_map.insert(
            "caller_stack_ids".into(),
            Value::Array(
                self.caller_stack_ids
                    .iter()
                    .map(|id| Value::String(format!("{}", id)))
                    .collect(),
            ),
        );
        state_map.insert(
            "ids_known_to_caller".into(),
            Value::Array(
                self.ids_known_to_caller
                    .iter()
                    .map(|id| Value::String(format!("{}", id)))
                    .collect(),
            ),
        );

        Value::Object(state_map)
    }
}

#[cfg(test)]
mod tests;
