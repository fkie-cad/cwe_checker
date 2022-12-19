//! The state module holds all information at CFG nodes that are generated from
//! the String Abstraction analysis.
//! Its content changes until a fixpoint is reached.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use itertools::Itertools;
use petgraph::graph::NodeIndex;

use crate::abstract_domain::{DataDomain, DomainInsertion, HasTop, TryToBitvec};
use crate::intermediate_representation::{ExternSymbol, Project, RuntimeMemoryImage};
use crate::{abstract_domain::IntervalDomain, prelude::*};
use crate::{
    abstract_domain::{AbstractDomain, AbstractIdentifier},
    analysis::pointer_inference::PointerInference as PointerInferenceComputation,
    analysis::pointer_inference::State as PointerInferenceState,
    intermediate_representation::{Expression, Sub, Variable},
};

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State<T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> {
    /// Keeps track of pointers that are returned by external calls
    /// where the location is temporarily unknown.
    unassigned_return_pointer: HashSet<DataDomain<IntervalDomain>>,
    /// Maps registers to pointer which point to abstract string domains.
    variable_to_pointer_map: HashMap<Variable, DataDomain<IntervalDomain>>,
    /// Maps stack offsets to pointers that have been stored on the stack
    /// These pointers point to abstract string domains.
    stack_offset_to_pointer_map: HashMap<i64, DataDomain<IntervalDomain>>,
    /// Tracks strings that lie directly on the stack.
    /// Maps the stack offset to the abstract string domain.
    stack_offset_to_string_map: HashMap<i64, T>,
    /// Maps the heap abstract identifier of an memory object to the corresponding string abstract domain
    /// representing its content.
    /// For simplicity reasons it is assumed that a heap object only represents one string at offset 0.
    heap_to_string_map: HashMap<AbstractIdentifier, T>,
    /// Holds the currently analyzed subroutine term
    current_sub: Arc<Option<Term<Sub>>>,
    /// The state of the pointer inference analysis.
    /// Used only for preventing unneccessary recomputation during handling of `Def`s in a basic block.
    /// It is set when handling `Def`s (except for the first `Def` in a block)
    /// provided that a corresponding pointer inference analysis state exists.
    /// Otherwise the field is ignored (including in the [merge](State::merge)-function) and usually set to `None`.
    #[serde(skip_serializing)]
    pointer_inference_state: Option<PointerInferenceState>,
}

impl<T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> AbstractDomain for State<T> {
    /// Merges two states.
    fn merge(&self, other: &Self) -> Self {
        let unassigned_return_pointer = self
            .unassigned_return_pointer
            .union(&other.unassigned_return_pointer)
            .cloned()
            .collect();

        let mut variable_to_pointer_map = self.variable_to_pointer_map.clone();

        for (var, other_pointer) in other.variable_to_pointer_map.iter() {
            if let Some(pointer) = self.variable_to_pointer_map.get(var) {
                variable_to_pointer_map.insert(var.clone(), pointer.merge(other_pointer));
            } else {
                variable_to_pointer_map.insert(var.clone(), other_pointer.clone());
            }
        }

        let mut stack_offset_to_pointer_map = self.stack_offset_to_pointer_map.clone();

        for (offset, other_pointer) in other.stack_offset_to_pointer_map.iter() {
            if let Some(pointer) = self.stack_offset_to_pointer_map.get(offset) {
                stack_offset_to_pointer_map.insert(*offset, pointer.merge(other_pointer));
            } else {
                stack_offset_to_pointer_map.insert(*offset, other_pointer.clone());
            }
        }

        let mut stack_offset_to_string_map = self.stack_offset_to_string_map.clone();

        for (offset, other_string_domain) in other.stack_offset_to_string_map.iter() {
            if let Some(string_domain) = self.stack_offset_to_string_map.get(offset) {
                stack_offset_to_string_map
                    .insert(*offset, string_domain.merge(other_string_domain));
            } else {
                stack_offset_to_string_map.insert(*offset, T::create_top_value_domain());
            }
        }

        let mut heap_to_string_map = self.heap_to_string_map.clone();

        for (id, other_string_domain) in other.heap_to_string_map.iter() {
            if let Some(string_domain) = self.heap_to_string_map.get(id) {
                heap_to_string_map.insert(id.clone(), string_domain.merge(other_string_domain));
            } else {
                heap_to_string_map.insert(id.clone(), T::create_top_value_domain());
            }
        }

        let mut new_state = State {
            unassigned_return_pointer,
            variable_to_pointer_map,
            stack_offset_to_pointer_map,
            stack_offset_to_string_map,
            heap_to_string_map,
            current_sub: self.current_sub.clone(),
            pointer_inference_state: self.pointer_inference_state.clone(),
        };

        new_state = new_state.delete_string_map_entries_if_no_pointer_targets_are_tracked();

        new_state
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl<T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> State<T> {
    /// Creates a new state.
    pub fn new(
        node_index: NodeIndex,
        pointer_inference_results: &PointerInferenceComputation,
    ) -> State<T> {
        let mut pi_state: Option<PointerInferenceState> = None;
        if let Some(pi_node) = pointer_inference_results.get_node_value(node_index) {
            pi_state = Some(pi_node.unwrap_value().clone());
        }

        let mut current_sub = None;
        if let Some(node) = pointer_inference_results
            .get_graph()
            .node_weight(node_index)
        {
            current_sub = Some(node.get_sub().clone());
        }

        State {
            unassigned_return_pointer: HashSet::new(),
            variable_to_pointer_map: HashMap::new(),
            stack_offset_to_pointer_map: HashMap::new(),
            stack_offset_to_string_map: HashMap::new(),
            heap_to_string_map: HashMap::new(),
            current_sub: Arc::new(current_sub),
            pointer_inference_state: pi_state,
        }
    }

    /// Removes all entries from the string maps.
    pub fn set_all_maps_empty(&mut self) {
        self.unassigned_return_pointer = HashSet::new();
        self.heap_to_string_map = HashMap::new();
        self.stack_offset_to_pointer_map = HashMap::new();
        self.stack_offset_to_string_map = HashMap::new();
        self.variable_to_pointer_map = HashMap::new();
    }

    /// Adds a return pointer to the unassigned return pointer set.
    pub fn add_unassigned_return_pointer(&mut self, pointer: DataDomain<IntervalDomain>) {
        self.unassigned_return_pointer.insert(pointer);
    }

    /// Returns the set of function return pointer that have not yet been assigned to
    /// a memory location or register.
    pub fn get_unassigned_return_pointer(&self) -> &HashSet<DataDomain<IntervalDomain>> {
        &self.unassigned_return_pointer
    }

    /// Adds a new variable to pointer entry to the map.
    pub fn add_new_variable_to_pointer_entry(
        &mut self,
        variable: Variable,
        pointer: DataDomain<IntervalDomain>,
    ) {
        self.variable_to_pointer_map.insert(variable, pointer);
    }

    /// Adds a new offset to string entry to the map.
    pub fn add_new_stack_offset_to_string_entry(&mut self, offset: i64, string_domain: T) {
        self.stack_offset_to_string_map
            .insert(offset, string_domain);
    }

    /// Adds a new heap id to string entry to the map.
    pub fn add_new_heap_to_string_entry(&mut self, heap_id: AbstractIdentifier, string_domain: T) {
        self.heap_to_string_map.insert(heap_id, string_domain);
    }

    /// Removes a string from the heap to string map for the given abstract id.
    pub fn remove_heap_to_string_entry(&mut self, heap_id: &AbstractIdentifier) {
        self.heap_to_string_map.remove(heap_id);
    }

    /// Returns a reference to the variable to pointer map.
    pub fn get_variable_to_pointer_map(&self) -> &HashMap<Variable, DataDomain<IntervalDomain>> {
        &self.variable_to_pointer_map
    }

    /// Sets the variable to pointer map to a new value.
    pub fn set_variable_to_pointer_map(
        &mut self,
        map: HashMap<Variable, DataDomain<IntervalDomain>>,
    ) {
        self.variable_to_pointer_map = map;
    }

    /// Returns a reference to the variable to pointer map.
    pub fn get_stack_offset_to_pointer_map(&self) -> &HashMap<i64, DataDomain<IntervalDomain>> {
        &self.stack_offset_to_pointer_map
    }

    /// Returns a reference to the stack offset to string map.
    pub fn get_stack_offset_to_string_map(&self) -> &HashMap<i64, T> {
        &self.stack_offset_to_string_map
    }

    /// Returns a reference to the heap to string map.
    pub fn get_heap_to_string_map(&self) -> &HashMap<AbstractIdentifier, T> {
        &self.heap_to_string_map
    }

    /// Gets the current subroutine since the analysis is interprocedural.
    pub fn get_current_sub(&self) -> Option<&Term<Sub>> {
        match &*self.current_sub {
            Some(sub) => Some(sub),
            None => None,
        }
    }

    /// Get the current pointer inference state if it is contained as an intermediate value in the state.
    pub fn get_pointer_inference_state(&self) -> Option<&PointerInferenceState> {
        self.pointer_inference_state.as_ref()
    }

    /// Set the current pointer inference state for `self`.
    pub fn set_pointer_inference_state(&mut self, pi_state: Option<PointerInferenceState>) {
        self.pointer_inference_state = pi_state;
    }

    /// Deletes all entries in the string maps that do not have corresponding pointers
    /// in the pointer maps.
    pub fn delete_string_map_entries_if_no_pointer_targets_are_tracked(&self) -> Self {
        let mut new_state = self.clone();
        if let Some(pi_state) = self.get_pointer_inference_state() {
            let (stack_strings, heap_strings) = self.filter_string_map_entries(pi_state);

            new_state.stack_offset_to_string_map = stack_strings;
            new_state.heap_to_string_map = heap_strings;
        }

        new_state
    }

    /// Returns a vector of all currently tracked pointers.
    pub fn collect_all_tracked_pointers(&self) -> Vec<DataDomain<IntervalDomain>> {
        let mut pointers: Vec<DataDomain<IntervalDomain>> =
            self.stack_offset_to_pointer_map.values().cloned().collect();
        let mut var_pointers = self.variable_to_pointer_map.values().cloned().collect();
        let mut unassigned_pointers: Vec<DataDomain<IntervalDomain>> =
            self.unassigned_return_pointer.iter().cloned().collect_vec();
        pointers.append(&mut var_pointers);
        pointers.append(&mut unassigned_pointers);

        pointers
    }

    /// Removes all string entries for which the pointers are not tracked anymore.
    pub fn filter_string_map_entries(
        &self,
        pi_state: &PointerInferenceState,
    ) -> (HashMap<i64, T>, HashMap<AbstractIdentifier, T>) {
        let mut stack_strings: HashMap<i64, T> = HashMap::new();
        let mut heap_strings: HashMap<AbstractIdentifier, T> = HashMap::new();
        for pointer in self.collect_all_tracked_pointers().iter() {
            for (target, offset) in pointer.get_relative_values().iter() {
                if State::<T>::is_stack_pointer(pi_state, target) {
                    if let Ok(offset_value) = offset.try_to_offset() {
                        if let Some((key, value)) =
                            self.stack_offset_to_string_map.get_key_value(&offset_value)
                        {
                            stack_strings.insert(*key, value.clone());
                        }
                    }
                } else if let Some((key, value)) = self.heap_to_string_map.get_key_value(target) {
                    heap_strings.insert(key.clone(), value.clone());
                }
            }
        }

        (stack_strings, heap_strings)
    }

    /// Evaluates the constant used as input of a Def Term.
    /// It checks whether it is a constant address pointing to global read only
    /// memory. If so, a pointer is added to the register map.
    pub fn evaluate_constant(
        &self,
        runtime_memory_image: &RuntimeMemoryImage,
        block_first_def_set: &HashSet<(Tid, Tid)>,
        constant: Bitvector,
    ) -> Option<DataDomain<IntervalDomain>> {
        if let Ok(address) = constant.try_to_u64() {
            if !block_first_def_set.iter().any(|(def_tid, _)| {
                u64::from_str_radix(def_tid.address.as_str(), 16).unwrap() == address
            }) && runtime_memory_image.is_global_memory_address(&constant)
                && runtime_memory_image
                    .read_string_until_null_terminator(&constant)
                    .is_ok()
            {
                return Some(DataDomain::from(IntervalDomain::new(
                    constant.clone(),
                    constant,
                )));
            }
        }

        None
    }

    /// Handles assign and load Def Terms.
    pub fn handle_assign_and_load(
        &mut self,
        output: &Variable,
        input: &Expression,
        runtime_memory_image: &RuntimeMemoryImage,
        block_first_def_set: &HashSet<(Tid, Tid)>,
        is_assign: bool,
    ) {
        let mut is_string_pointer = false;
        if let Some(pi_state) = self.clone().get_pointer_inference_state() {
            is_string_pointer = self.check_if_output_is_string_pointer_and_add_targets(
                pi_state,
                output,
                runtime_memory_image,
                block_first_def_set,
            )
        } else if is_assign {
            is_string_pointer = self.add_global_pointer_if_input_is_string_constant(
                runtime_memory_image,
                block_first_def_set,
                output,
                input,
            )
        }

        // If the output variable is tracked and the new data is not a string pointer,
        // remove the variable from the pointer map.
        if !is_string_pointer {
            self.variable_to_pointer_map.remove(output);
        }
    }

    /// Checks whether the given pointer points to a string and adds missing targets
    /// to the string maps as *Top* values.
    pub fn check_if_output_is_string_pointer_and_add_targets(
        &mut self,
        pi_state: &PointerInferenceState,
        output: &Variable,
        runtime_memory_image: &RuntimeMemoryImage,
        block_first_def_set: &HashSet<(Tid, Tid)>,
    ) -> bool {
        let output_domain = pi_state.eval(&Expression::Var(output.clone()));
        if let Some(value) = output_domain.get_absolute_value() {
            if let Ok(constant) = value.try_to_bitvec() {
                if let Some(global_pointer) =
                    self.evaluate_constant(runtime_memory_image, block_first_def_set, constant)
                {
                    self.variable_to_pointer_map
                        .insert(output.clone(), global_pointer);
                    self.add_relative_targets_to_string_maps(pi_state, &output_domain);

                    return true;
                }
            }
        } else if !output_domain.get_relative_values().is_empty() {
            return self.pointer_added_to_variable_maps(pi_state, output, output_domain);
        }

        false
    }

    /// If the input is a string constant, add the global pointer to the variable map.
    pub fn add_global_pointer_if_input_is_string_constant(
        &mut self,
        runtime_memory_image: &RuntimeMemoryImage,
        block_first_def_set: &HashSet<(Tid, Tid)>,
        output: &Variable,
        input: &Expression,
    ) -> bool {
        if let Expression::Const(constant) = input {
            if let Some(global_pointer) =
                self.evaluate_constant(runtime_memory_image, block_first_def_set, constant.clone())
            {
                self.variable_to_pointer_map
                    .insert(output.clone(), global_pointer);

                return true;
            }
        }

        false
    }

    /// Adds all relative targets of the given DataDomain to the string maps
    /// if they are not already tracked.
    pub fn add_relative_targets_to_string_maps(
        &mut self,
        pi_state: &PointerInferenceState,
        pointer: &DataDomain<IntervalDomain>,
    ) {
        for (target, offset) in pointer.get_relative_values().iter() {
            if State::<T>::is_stack_pointer(pi_state, target) {
                if let Ok(offset_value) = offset.try_to_offset() {
                    self.stack_offset_to_string_map
                        .entry(offset_value)
                        .or_insert_with(T::create_top_value_domain);
                }
            } else if !self.heap_to_string_map.contains_key(target) {
                self.heap_to_string_map
                    .insert(target.clone(), T::create_top_value_domain());
            }
        }
    }

    /// Adds a pointer to the variable pointer maps if its targets were fully or partially tracked.
    /// Returns true if it was added.
    pub fn pointer_added_to_variable_maps(
        &mut self,
        pi_state: &PointerInferenceState,
        output: &Variable,
        loaded_pointer: DataDomain<IntervalDomain>,
    ) -> bool {
        if self.unassigned_return_pointer.contains(&loaded_pointer) {
            self.variable_to_pointer_map
                .insert(output.clone(), loaded_pointer.clone());
            self.unassigned_return_pointer.remove(&loaded_pointer);
            true
        } else if self.pointer_is_in_pointer_maps(&loaded_pointer)
            || self.pointer_targets_partially_tracked(pi_state, &loaded_pointer)
        {
            self.variable_to_pointer_map
                .insert(output.clone(), loaded_pointer);
            true
        } else {
            false
        }
    }

    /// Adds a pointer to the stack pointer maps if its targets were fully or partially tracked.
    pub fn pointer_added_to_stack_maps(
        &mut self,
        pi_state: &PointerInferenceState,
        target_address: &Expression,
        potential_string_pointer: DataDomain<IntervalDomain>,
    ) -> bool {
        if self
            .unassigned_return_pointer
            .contains(&potential_string_pointer)
        {
            self.unassigned_return_pointer
                .remove(&potential_string_pointer);
            self.add_pointer_to_stack_map(target_address, potential_string_pointer);
            true
        } else if self.pointer_is_in_pointer_maps(&potential_string_pointer)
            || self.pointer_targets_partially_tracked(pi_state, &potential_string_pointer)
        {
            self.add_pointer_to_stack_map(target_address, potential_string_pointer);
            true
        } else {
            false
        }
    }

    /// If only some targets of a pointer point to tracked strings, add top values for the
    /// other targets. It is assumed that all targets point to the same data type.
    pub fn pointer_targets_partially_tracked(
        &mut self,
        pi_state: &PointerInferenceState,
        pointer: &DataDomain<IntervalDomain>,
    ) -> bool {
        let mut contains_string_target = false;
        let mut new_stack_entries: Vec<i64> = Vec::new();
        let mut new_heap_entries: Vec<AbstractIdentifier> = Vec::new();
        for (target, offset) in pointer.get_relative_values().iter() {
            if State::<T>::is_stack_pointer(pi_state, target) {
                if let Ok(offset_value) = offset.try_to_offset() {
                    if self.stack_offset_to_string_map.contains_key(&offset_value) {
                        contains_string_target = true;
                    } else {
                        new_stack_entries.push(offset_value);
                    }
                }
            } else if self.heap_to_string_map.contains_key(target) {
                contains_string_target = true;
            } else {
                new_heap_entries.push(target.clone());
            }
        }

        if contains_string_target {
            self.add_top_domain_values_for_additional_pointer_targets(
                new_stack_entries,
                new_heap_entries,
            )
        }

        contains_string_target
    }

    /// Adds *Top* values to stack and heap maps for additional pointer targets.
    pub fn add_top_domain_values_for_additional_pointer_targets(
        &mut self,
        new_stack_entries: Vec<i64>,
        new_heap_entries: Vec<AbstractIdentifier>,
    ) {
        for entry in new_stack_entries.iter() {
            self.stack_offset_to_string_map
                .insert(*entry, T::create_top_value_domain());
        }
        for entry in new_heap_entries.iter() {
            self.heap_to_string_map
                .insert(entry.clone(), T::create_top_value_domain());
        }
    }

    /// Checks whether a given pointer is contained in one of the pointer maps.
    pub fn pointer_is_in_pointer_maps(&self, pointer: &DataDomain<IntervalDomain>) -> bool {
        self.stack_offset_to_pointer_map
            .iter()
            .any(|(_, tracked_value)| tracked_value == pointer)
            || self
                .variable_to_pointer_map
                .iter()
                .any(|(_, tracked_value)| tracked_value == pointer)
    }

    /// Handles store Def Terms.
    pub fn handle_store(
        &mut self,
        target_address: &Expression,
        value: &Expression,
        runtime_memory_image: &RuntimeMemoryImage,
        block_first_def_set: &HashSet<(Tid, Tid)>,
    ) {
        match value {
            Expression::Const(constant) => {
                if let Some(data) = self.evaluate_constant(
                    runtime_memory_image,
                    block_first_def_set,
                    constant.clone(),
                ) {
                    self.add_pointer_to_stack_map(target_address, data);
                }
            }
            _ => {
                if let Some(pi_state) = self.get_pointer_inference_state().cloned() {
                    let potential_string_pointer = pi_state.eval(value);
                    if !self.pointer_added_to_stack_maps(
                        &pi_state,
                        target_address,
                        potential_string_pointer.clone(),
                    ) {
                        if let Some(constant) = potential_string_pointer.get_absolute_value() {
                            if let Ok(constant_value) = constant.try_to_bitvec() {
                                self.handle_store(
                                    target_address,
                                    &Expression::Const(constant_value),
                                    runtime_memory_image,
                                    block_first_def_set,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    /// If a string pointer is to be stored on the stack, add it to the stack map.
    pub fn add_pointer_to_stack_map(
        &mut self,
        target: &Expression,
        string_pointer: DataDomain<IntervalDomain>,
    ) {
        if let Some(pi_state) = self.get_pointer_inference_state().cloned() {
            let pointer = pi_state.eval(target);
            for (target, offset) in pointer.get_relative_values().iter() {
                if State::<T>::is_stack_pointer(&pi_state, target) {
                    if let Ok(offset_value) = offset.try_to_offset() {
                        self.stack_offset_to_pointer_map
                            .insert(offset_value, string_pointer.clone());
                    }
                }
            }
        }
    }

    /// Removes all non callee saved register entries from the variable to pointer map.
    pub fn remove_non_callee_saved_pointer_entries_for_external_symbol(
        &mut self,
        project: &Project,
        extern_symbol: &ExternSymbol,
    ) {
        let cconv = project.get_calling_convention(extern_symbol);
        let mut filtered_map = self.variable_to_pointer_map.clone();
        for (register, _) in self.variable_to_pointer_map.clone().iter() {
            if !cconv.callee_saved_register.contains(register) {
                if let Some(pointer) = filtered_map.remove(register) {
                    self.unassigned_return_pointer.insert(pointer);
                }
            }
        }

        self.variable_to_pointer_map = filtered_map;
    }

    /// Checks whether a target refers to the Stack.
    pub fn is_stack_pointer(pi_state: &PointerInferenceState, target: &AbstractIdentifier) -> bool {
        pi_state.stack_id == *target
    }
}

#[cfg(test)]
mod tests;
