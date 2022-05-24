//! This module handles the string processing at external symbol calls.

use regex::Regex;
use std::collections::BTreeMap;

use crate::abstract_domain::{
    AbstractIdentifier, DomainInsertion, HasTop, IntervalDomain, TryToBitvec,
};
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::intermediate_representation::{Bitvector, Datatype};
use crate::{abstract_domain::AbstractDomain, intermediate_representation::ExternSymbol};

use super::super::state::State;
use super::Context;

mod memcpy;
mod scanf;
mod sprintf;
mod strcat;

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
    /// Handles generic symbol calls by deleting all non callee saved pointer entries.
    pub fn handle_generic_symbol_calls(
        &self,
        extern_symbol: &ExternSymbol,
        state: &State<T>,
    ) -> State<T> {
        let mut new_state = state.clone();
        new_state.remove_non_callee_saved_pointer_entries_for_external_symbol(
            self.project,
            extern_symbol,
        );

        new_state
    }

    /// Handles calls to external symbols for which no ExternSymbol object is known.
    pub fn handle_unknown_symbol_calls(&self, state: &mut State<T>) {
        if let Some(standard_cconv) = self.project.get_standard_calling_convention() {
            let mut filtered_map = state.get_variable_to_pointer_map().clone();
            for (register, _) in state.get_variable_to_pointer_map().clone().iter() {
                if !standard_cconv.callee_saved_register.contains(register) {
                    filtered_map.remove(register);
                }
            }

            state.set_variable_to_pointer_map(filtered_map);
        }
    }

    /// The output of a string symbol is added to the map of abstract strings.
    /// If the symbol returns a format string, the string is approximated
    /// as good as possible by checking the input parameters.
    pub fn handle_string_symbol_calls(
        &self,
        extern_symbol: &ExternSymbol,
        state: &State<T>,
    ) -> State<T> {
        let mut new_state = match extern_symbol.name.as_str() {
            "scanf" | "__isoc99_scanf" => self.handle_scanf_calls(state, extern_symbol),
            "sscanf" | "__isoc99_sscanf" => self.handle_sscanf_calls(state, extern_symbol),
            "sprintf" | "snprintf" | "vsprintf" | "vsnprintf" => {
                self.handle_sprintf_and_snprintf_calls(state, extern_symbol)
            }
            "strcat" | "strncat" => self.handle_strcat_and_strncat_calls(state, extern_symbol),
            "memcpy" => self.handle_memcpy_calls(state, extern_symbol),
            "free" => self.handle_free(state, extern_symbol),
            _ => panic!("Unexpected Extern Symbol."),
        };

        new_state.remove_non_callee_saved_pointer_entries_for_external_symbol(
            self.project,
            extern_symbol,
        );

        new_state
    }

    /// Takes the pointer target if there is only one and checks whether the target
    /// is inside the current stack frame. If so, the string domain is added to the
    /// analysis.
    pub fn add_new_string_abstract_domain(
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        pointer: &BTreeMap<AbstractIdentifier, IntervalDomain>,
        domain_input_string: T,
    ) {
        for (target, offset) in pointer.iter() {
            if pi_state.stack_id == *target {
                if let Ok(offset_value) = offset.try_to_offset() {
                    state.add_new_stack_offset_to_string_entry(
                        offset_value,
                        domain_input_string.clone(),
                    );
                }
            } else {
                state.add_new_heap_to_string_entry(target.clone(), domain_input_string.clone());
            }
        }
    }

    /// Regex that filters format specifier from a format string.
    pub fn re_format_specifier() -> Regex {
        Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#).expect("No valid regex!")
    }

    /// Merges domains from multiple pointer targets. The merged domain serves as input to a format string.
    /// If one of the targets does not contain a domain or the offset of a stack target cannot be parsed,
    /// a *Top* value is returned as no assumption can be made about the input.
    pub fn merge_domains_from_multiple_pointer_targets(
        state: &State<T>,
        pi_state: &PointerInferenceState,
        pointer: &BTreeMap<AbstractIdentifier, IntervalDomain>,
    ) -> T {
        let mut domains: Vec<T> = Vec::new();
        for (target, offset) in pointer.iter() {
            // Check the stack offset map if the target points to a stack position.
            if pi_state.stack_id == *target {
                if let Ok(offset_value) = offset.try_to_offset() {
                    if let Some(domain) = state.get_stack_offset_to_string_map().get(&offset_value)
                    {
                        domains.push(domain.clone());
                    } else {
                        return T::create_top_value_domain();
                    }
                } else {
                    return T::create_top_value_domain();
                }
            } else {
                // Check the heap map if the target points to a heap position.
                if let Some(domain) = state.get_heap_to_string_map().get(target) {
                    domains.push(domain.clone());
                } else {
                    return T::create_top_value_domain();
                }
            }
        }

        let mut init_domain = domains.first().unwrap().clone();
        domains.remove(0);
        for remaining_domain in domains.iter() {
            init_domain = init_domain.merge(remaining_domain);
        }

        init_domain
    }

    /// Calls the appropriate data type approximator.
    pub fn approximate_string_domain_from_datatype(specifier: String) -> T {
        match Datatype::from(specifier) {
            Datatype::Char => T::create_char_domain(),
            Datatype::Integer => T::create_integer_domain(),
            Datatype::Pointer => T::create_pointer_value_domain(),
            Datatype::Double | Datatype::Long | Datatype::LongDouble | Datatype::LongLong => {
                T::create_float_value_domain()
            }
            _ => panic!("Invalid data type specifier from format string."),
        }
    }

    /// Inserts an integer constant into the format string.
    pub fn get_constant_integer_domain(constant: Bitvector) -> Option<T> {
        if let Ok(integer) = constant.try_to_i64() {
            return Some(T::from(integer.to_string()));
        }

        None
    }

    /// Inserts a char constant into the format string.
    pub fn get_constant_char_domain(&self, constant: Bitvector) -> Option<T> {
        if let Ok(Some(char_code)) = self.project.runtime_memory_image.read(
            &constant,
            self.project
                .datatype_properties
                .get_size_from_data_type(Datatype::Char),
        ) {
            if let Some(c_char) = Context::<T>::parse_bitvec_to_char(char_code) {
                return Some(T::from(c_char.to_string()));
            }
        } else if let Some(c_char) = Context::<T>::parse_bitvec_to_char(constant.clone()) {
            return Some(T::from(c_char.to_string()));
        }

        None
    }

    /// Parses a bitvector to a char if possible.
    pub fn parse_bitvec_to_char(char_code: Bitvector) -> Option<char> {
        if let Ok(code) = char_code.try_to_u32() {
            if let Some(c_char) = std::char::from_u32(code) {
                return Some(c_char);
            }
        }

        None
    }

    /// Inserts a string constant into the format string.
    pub fn get_constant_string_domain(&self, constant: Bitvector) -> Option<T> {
        if let Ok(string) = self
            .project
            .runtime_memory_image
            .read_string_until_null_terminator(&constant)
        {
            if !string.is_empty() {
                return Some(T::from(string.to_string()));
            }
        }

        None
    }

    /// Deletes string entries in the heap to string map if the corresponding pointer is used
    /// to free memory space.
    pub fn handle_free(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();

        if let Some(dest_arg) = extern_symbol.parameters.first() {
            if let Some(pi_state) = state.get_pointer_inference_state() {
                if let Ok(pointer) =
                    pi_state.eval_parameter_arg(dest_arg, &self.project.runtime_memory_image)
                {
                    let heap_to_string_map = state.get_heap_to_string_map();
                    for (target, _) in pointer.get_relative_values().iter() {
                        if heap_to_string_map.contains_key(target) {
                            new_state.remove_heap_to_string_entry(target);
                        }
                    }
                }
            }
        }

        new_state
    }
}

#[cfg(test)]
pub mod tests;
