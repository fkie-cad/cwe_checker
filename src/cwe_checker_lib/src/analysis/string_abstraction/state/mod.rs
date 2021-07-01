use std::collections::HashMap;

use apint::BitWidth;

use crate::abstract_domain::HasTop;
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
    /// Tracks strings that lie directly on the stack.
    /// Maps the stack offset to the abstract identifier of the string.
    stack_offset_to_string_map: HashMap<Bitvector, AbstractIdentifier>,
    /// Tracks pointers to strings that have been stored on the stack.
    /// Maps the offset on the stack to the corresponding pointer domain.
    stack_offset_to_pointer_map: HashMap<Bitvector, PointerDomain<IntervalDomain>>,
    /// Maps a register to a pointer which points to an abstract identifier.
    /// The abstract identifier identifies the abstract string.
    variable_to_pointer_map: HashMap<Variable, PointerDomain<IntervalDomain>>,
    /// Maps the abstract identifier of an memory object to the corresponding string abstract domain
    /// representing its content.
    strings: HashMap<AbstractIdentifier, T>,
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
    /// For each abstract identifier that is in both 'strings' fields,
    /// the string domains are merged.
    /// If the one state has an Abstract Identifier that is not in the other,
    /// it is added to the 'strings' map.
    fn merge(&self, other: &Self) -> Self {
        let mut stack_offset_to_string_map = self.stack_offset_to_string_map.clone();
        let mut stack_offset_to_pointer_map = self.stack_offset_to_pointer_map.clone();

        let mut variable_to_pointer_map: HashMap<Variable, PointerDomain<IntervalDomain>> =
            self.variable_to_pointer_map.clone();

        for (var, other_pointer) in other.variable_to_pointer_map.iter() {
            if let Some(pointer) = self.variable_to_pointer_map.get(var) {
                variable_to_pointer_map.insert(var.clone(), pointer.merge(other_pointer));
            } else {
                variable_to_pointer_map.insert(var.clone(), other_pointer.clone());
            }
        }

        let mut strings: HashMap<AbstractIdentifier, T> = self.strings.clone();

        for (tid, other_abstract_string) in other.strings.iter() {
            if let Some(abstract_string) = strings.get_mut(tid) {
                abstract_string.merge(other_abstract_string);
            } else {
                strings.insert(tid.clone(), other_abstract_string.clone());
            }
        }

        State {
            stack_offset_to_string_map,
            stack_offset_to_pointer_map,
            variable_to_pointer_map,
            strings,
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
    /// Adds a new offset to string entry to the map.
    pub fn add_new_offset_to_string_entry(
        &mut self,
        offset: Bitvector,
        identifier: AbstractIdentifier,
    ) {
        self.stack_offset_to_string_map.insert(offset, identifier);
    }

    /// Adds a new offset to pointer entry to the map.
    pub fn add_new_offset_to_pointer_entry(
        &mut self,
        offset: Bitvector,
        pointer: PointerDomain<IntervalDomain>,
    ) {
        self.stack_offset_to_pointer_map.insert(offset, pointer);
    }

    /// Adds the top value of a domain to the strings map.
    pub fn add_string_top_value(&mut self, abstract_id: AbstractIdentifier) {
        let generic_string_top_value = T::from("".to_string()).top();
        self.strings.insert(abstract_id, generic_string_top_value);
    }

    /// Adds a new entry to the strings container.
    pub fn add_string_domain(&mut self, abstract_id: AbstractIdentifier, string: String) {
        self.strings.insert(abstract_id, T::from(string));
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
                        );
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
}

#[cfg(test)]
mod tests;
