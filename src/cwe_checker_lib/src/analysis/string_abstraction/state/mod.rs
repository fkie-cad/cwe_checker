use std::collections::{HashMap, HashSet};

use crate::abstract_domain::HasTop;
use crate::intermediate_representation::{ExternSymbol, Project};
use crate::{abstract_domain::IntervalDomain, prelude::*};
use crate::{
    abstract_domain::{AbstractDomain, AbstractIdentifier, AbstractLocation, PointerDomain},
    analysis::pointer_inference::State as PointerInferenceState,
    intermediate_representation::{Def, Expression, Sub, Variable},
    utils::binary::RuntimeMemoryImage,
};

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State<T: AbstractDomain + Eq> {
    /// Keeps track of pointers that are returned by external calls
    /// where the location is temporarily unknown.
    unassigned_return_pointer: HashSet<PointerDomain<IntervalDomain>>,
    /// Maps registers to pointer which point to abstract string domains.
    variable_to_pointer_map: HashMap<Variable, PointerDomain<IntervalDomain>>,
    /// Maps stack offsets to pointers that have been stored on the stack
    /// These pointers point to abstract string domains.
    stack_offset_to_pointer_map: HashMap<i64, PointerDomain<IntervalDomain>>,
    /// Tracks strings that lie directly on the stack.
    /// Maps the stack offset to the abstract string domain.
    stack_offset_to_string_map: HashMap<i64, T>,
    /// Maps the heap abstract identifier of an memory object to the corresponding string abstract domain
    /// representing its content.
    /// For simplicity reasons it is assumed that a heap object only represents one string at offset 0.
    heap_to_string_map: HashMap<AbstractIdentifier, T>,
    /// Holds the currently analyzed subroutine term
    current_sub: Option<Term<Sub>>,
    /// The state of the pointer inference analysis.
    /// Used only for preventing unneccessary recomputation during handling of `Def`s in a basic block.
    /// It is set when handling `Def`s (except for the first `Def` in a block)
    /// provided that a corresponding pointer inference analysis state exists.
    /// Otherwise the field is ignored (including in the [merge](State::merge)-function) and usually set to `None`.
    #[serde(skip_serializing)]
    pointer_inference_state: Option<PointerInferenceState>,
}

impl<T: AbstractDomain + Eq> AbstractDomain for State<T> {
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
                stack_offset_to_pointer_map.insert(offset.clone(), pointer.merge(other_pointer));
            } else {
                stack_offset_to_pointer_map.insert(offset.clone(), other_pointer.clone());
            }
        }

        let mut stack_offset_to_string_map = self.stack_offset_to_string_map.clone();

        for (offset, other_string_domain) in other.stack_offset_to_string_map.iter() {
            if let Some(string_domain) = self.stack_offset_to_string_map.get(offset) {
                stack_offset_to_string_map
                    .insert(offset.clone(), string_domain.merge(other_string_domain));
            } else {
                stack_offset_to_string_map.insert(offset.clone(), other_string_domain.clone());
            }
        }

        let mut heap_to_string_map = self.heap_to_string_map.clone();

        for (id, other_string_domain) in other.heap_to_string_map.iter() {
            if let Some(string_domain) = self.heap_to_string_map.get(id) {
                heap_to_string_map.insert(id.clone(), string_domain.merge(other_string_domain));
            } else {
                heap_to_string_map.insert(id.clone(), other_string_domain.clone());
            }
        }

        State {
            unassigned_return_pointer,
            variable_to_pointer_map,
            stack_offset_to_pointer_map,
            stack_offset_to_string_map,
            heap_to_string_map,
            current_sub: self.current_sub.clone(),
            pointer_inference_state: None,
        }
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl<T: AbstractDomain + HasTop + Eq + From<String>> State<T> {
    /// Adds a return pointer to the unassigned return pointer set.
    pub fn add_unassigned_return_pointer(&mut self, pointer: PointerDomain<IntervalDomain>) {
        self.unassigned_return_pointer.insert(pointer);
    }

    /// Adds a new variable to pointer entry to the map.
    pub fn add_new_variable_to_pointer_entry(
        &mut self,
        variable: Variable,
        pointer: PointerDomain<IntervalDomain>,
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

    /// Returns a reference to the stack offset to string map.
    pub fn get_stack_offset_to_string_map(&self) -> &HashMap<i64, T> {
        &self.stack_offset_to_string_map
    }

    /// Returns a reference to the heap to string map.
    pub fn get_heap_to_string_map(&self) -> &HashMap<AbstractIdentifier, T> {
        &self.heap_to_string_map
    }

    /// Gets the current subroutine since the analysis is interprocedural.
    pub fn get_current_sub(&self) -> Option<Term<Sub>> {
        self.current_sub.clone()
    }

    /// Get the current pointer inference state if it is contained as an intermediate value in the state.
    pub fn get_pointer_inference_state(&self) -> Option<&PointerInferenceState> {
        self.pointer_inference_state.as_ref()
    }

    /// Set the current pointer inference state for `self`.
    pub fn set_pointer_inference_state(&mut self, pi_state: Option<PointerInferenceState>) {
        self.pointer_inference_state = pi_state;
    }

    /// Evaluates the constant used as input of a Def Term.
    /// It checks whether it is a constant address pointing to global read only
    /// memory. If so, the string is extracted and a new String Domain with pointers
    /// is created.
    pub fn evaluate_constant(
        &mut self,
        runtime_memory_image: &RuntimeMemoryImage,
        output: &Variable,
        tid: Tid,
        constant: Bitvector,
    ) {
        if runtime_memory_image.is_global_memory_address(&constant) {
            match runtime_memory_image.read_string_until_null_terminator(&constant) {
                Ok(string) => {
                    if let Ok(abstract_location) = AbstractLocation::from_var(output) {
                        let abstract_id = AbstractIdentifier::new(tid, abstract_location);
                        /*
                        self.strings
                            .insert(abstract_id.clone(), T::from(string.to_string()));
                        self.variable_to_pointer_map.insert(
                            output.clone(),
                            PointerDomain::new(
                                abstract_id,
                                IntervalDomain::from(Bitvector::zero(
                                    BitWidth::new(output.size.as_bit_length()).unwrap(),
                                )),
                            ),
                        ); */
                    }
                }
                // TODO: Change to log
                Err(e) => panic!("{}", e),
            }
        }
    }

    /// Handles assign and load Def Terms.
    pub fn handle_assign_and_load(
        &mut self,
        def: &Term<Def>,
        input: &Expression,
        output: &Variable,
        runtime_memory_image: &RuntimeMemoryImage,
    ) {
        match input {
            Expression::Const(constant) => self.evaluate_constant(
                runtime_memory_image,
                output,
                def.tid.clone(),
                constant.clone(),
            ),
            Expression::Var(input_register) => {
                if let Some(pointer) = self.variable_to_pointer_map.remove(input_register) {
                    self.variable_to_pointer_map.insert(output.clone(), pointer);
                }
            }
            Expression::BinOp { op, lhs, rhs } => {}
            _ => (),
        }
    }

    /// Removes all non callee saved register entries from the variable to pointer map.
    pub fn remove_non_callee_saved_pointer_entries(
        &mut self,
        project: &Project,
        extern_symbol: &ExternSymbol,
    ) {
        let cconv = extern_symbol.get_calling_convention(project);
        let mut filtered_map = self.variable_to_pointer_map.clone();
        for (register, _) in self.variable_to_pointer_map.clone().iter() {
            if !cconv.callee_saved_register.contains(&register.name) {
                filtered_map.remove(register);
            }
        }

        self.variable_to_pointer_map = filtered_map;
    }
}

#[cfg(test)]
mod tests;
