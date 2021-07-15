use regex::{Match, Regex};
use std::collections::HashMap;

use crate::prelude::*;

use anyhow::Error;
use itertools::izip;

use crate::abstract_domain::{
    DataDomain, DomainInsertion, HasTop, IntervalDomain, PointerDomain, TryToBitvec,
};
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::intermediate_representation::{Arg, Bitvector, Datatype};
use crate::utils::arguments::{
    get_input_format_string, get_variable_parameters, parse_format_string_parameters,
};
use crate::{abstract_domain::AbstractDomain, intermediate_representation::ExternSymbol};

use super::super::state::State;
use super::Context;

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
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
            "sprintf" | "snprintf" => self.handle_sprintf_and_snprintf_calls(state, extern_symbol),
            "strcat" | "strncat" => self.handle_strcat_and_strncat_calls(state, extern_symbol),
            "free" => self.handle_free(state, extern_symbol),
            _ => panic!("Unexpected Extern Symbol."),
        };

        new_state.remove_non_callee_saved_pointer_entries(self.project, extern_symbol);

        new_state
    }

    /// Handles the detection of string parameters to scanf calls.
    /// Adds new string abstract domains to the current state.
    pub fn handle_scanf_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            // Check whether the format string parameters can be parsed.
            if let Ok(return_values) = get_variable_parameters(
                self.project,
                pi_state,
                extern_symbol,
                &*self.format_string_index_map,
                self.runtime_memory_image,
            ) {
                self.create_abstract_domain_entries_for_function_return_values(
                    pi_state,
                    &mut new_state,
                    return_values.into_iter().map(|arg| (arg, None)).collect(),
                );
            }
        }

        new_state
    }

    pub fn create_abstract_domain_entries_for_function_return_values(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State<T>,
        arg_to_value_map: HashMap<Arg, Option<String>>,
    ) {
        for (argument, value) in arg_to_value_map.into_iter() {
            if let Ok(DataDomain::Pointer(return_pointer)) = pi_state.eval_parameter_arg(
                &argument,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                if let Some(string) = value {
                    Context::add_new_string_abstract_domain(
                        state,
                        pi_state,
                        &return_pointer,
                        T::from(string),
                    );
                } else {
                    Context::add_new_string_abstract_domain(
                        state,
                        pi_state,
                        &return_pointer,
                        T::create_top_value_domain(),
                    );
                }

                state.add_unassigned_return_pointer(return_pointer);
            }
        }
    }

    pub fn handle_sscanf_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(source_string_arg) = extern_symbol.parameters.first() {
                if let Ok(DataDomain::Value(address)) = pi_state.eval_parameter_arg(
                    source_string_arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    if let Ok(source_string) =
                        self.runtime_memory_image.read_string_until_null_terminator(
                            &address
                                .try_to_bitvec()
                                .expect("Could not translate interval address to bitvector."),
                        )
                    {
                        if let Ok(source_return_string_map) = self
                            .map_source_string_parameters_to_return_arguments(
                                pi_state,
                                extern_symbol,
                                source_string,
                            )
                        {
                            self.create_abstract_domain_entries_for_function_return_values(
                                pi_state,
                                &mut new_state,
                                source_return_string_map,
                            );
                        }
                    }
                } else {
                    // In case the source string is unknown, the call can be treated the same as
                    // a scanf call.
                    new_state = self.handle_scanf_calls(&new_state, extern_symbol);
                }
            }
        }

        new_state
    }

    pub fn map_source_string_parameters_to_return_arguments(
        &self,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
        source_string: &str,
    ) -> Result<HashMap<Arg, Option<String>>, Error> {
        if let Ok(string_parameters) = get_variable_parameters(
            self.project,
            pi_state,
            extern_symbol,
            &*self.format_string_index_map,
            self.runtime_memory_image,
        ) {
            // We already know the format string exists at this point.
            let format_string = get_input_format_string(
                pi_state,
                extern_symbol,
                *self.format_string_index_map.get("sscanf").unwrap(),
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            )
            .unwrap();
            let all_parameters: Vec<Datatype> = parse_format_string_parameters(
                format_string.as_str(),
                &self.project.datatype_properties,
            )
            .unwrap()
            .into_iter()
            .map(|(data_type, _)| data_type)
            .collect();

            let return_values: Vec<String> =
                source_string.split(" ").map(|s| s.to_string()).collect();

            // Filter out all non string return values.
            let string_values: Vec<Option<String>> = izip!(all_parameters, return_values)
                .filter_map(|(data_type, value)| {
                    if matches!(data_type, Datatype::Pointer) {
                        Some(Some(value))
                    } else {
                        None
                    }
                })
                .collect();

            return Ok(izip!(string_parameters, string_values).collect());
        }

        Err(anyhow!("Could not map source string to return parameters."))
    }

    /// Takes the pointer target if there is only one and checks whether the target
    /// is inside the current stack frame. If so, the string domain is added to the
    /// analysis.
    pub fn add_new_string_abstract_domain(
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        pointer: &PointerDomain<IntervalDomain>,
        domain_input_string: T,
    ) {
        for (target, offset) in pointer.targets().iter() {
            if pi_state.caller_stack_ids.contains(target) || pi_state.stack_id == *target {
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

    /// Handles the detection of string parameters to sprintf and snprintf calls.
    /// Is able to identify a string constant parameter and to insert it into the format string.
    /// e.g. the format string is "cat %s" and the analysis detected that the input string
    /// is a constant in memory, for instance "bash.sh".
    /// Then the abstract string domain is constructed with the string "cat bash.sh".
    pub fn handle_sprintf_and_snprintf_calls(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
    ) -> State<T> {
        let mut new_state = state.clone();
        if let Some(return_arg) = extern_symbol.parameters.first() {
            if let Some(pi_state) = state.get_pointer_inference_state() {
                if let Ok(DataDomain::Pointer(return_pointer)) = pi_state.eval_parameter_arg(
                    return_arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    let format_string_index = self
                        .format_string_index_map
                        .get(&extern_symbol.name)
                        .unwrap();
                    if let Ok(input_format_string) = get_input_format_string(
                        pi_state,
                        extern_symbol,
                        *format_string_index,
                        &self.project.stack_pointer_register,
                        self.runtime_memory_image,
                    ) {
                        let returned_abstract_domain = self
                            .create_string_domain_for_sprintf_snprintf(
                                pi_state,
                                state,
                                extern_symbol,
                                input_format_string,
                            );

                        Context::<T>::add_new_string_abstract_domain(
                            &mut new_state,
                            pi_state,
                            &return_pointer,
                            returned_abstract_domain,
                        );
                    } else {
                        Context::<T>::add_new_string_abstract_domain(
                            &mut new_state,
                            pi_state,
                            &return_pointer,
                            T::from("".to_string()).top(),
                        );
                    }
                }
            }
        }

        new_state
    }

    /// Creates a string domain for a s(n)printf call by considering input constants
    /// and other domains.
    pub fn create_string_domain_for_sprintf_snprintf(
        &self,
        pi_state: &PointerInferenceState,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
        input_format_string: String,
    ) -> T {
        let mut processed_string = input_format_string.clone();
        let mut filtered_args: Vec<Arg> = vec![];
        if let Ok(mut var_args) = get_variable_parameters(
            self.project,
            pi_state,
            extern_symbol,
            &*self.format_string_index_map,
            self.runtime_memory_image,
        ) {
            // Insert constants into the format string if available and
            // filter out all args that represent those constants.
            processed_string = self.insert_constant_values_into_format_string(
                processed_string,
                &mut var_args,
                pi_state,
            );

            filtered_args = var_args;
        }

        self.create_string_domain_and_insert_approximations_for_format_specifier(
            &state,
            filtered_args,
            processed_string.clone(),
            processed_string == input_format_string,
            pi_state,
        )
    }

    /// Splits a format string by its identifiers and keeps the delimiters.
    /// During the split, string domains are created from the constant parts of the format string
    /// and the remaining domains are approximated according to the datatype of the format specifier.
    pub fn create_string_domain_and_insert_approximations_for_format_specifier(
        &self,
        state: &State<T>,
        filtered_args: Vec<Arg>,
        format_string: String,
        constants_inserted: bool,
        pi_state: &PointerInferenceState,
    ) -> T {
        let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
        .expect("No valid regex!");
        let mut split_string: Vec<T> = Vec::new();
        let mut last_end_index = 0;
        for (index, (specifier, arg)) in re
            .find_iter(&format_string.clone())
            .zip(filtered_args)
            .enumerate()
        {
            // Create a domain for the first substring if the string does not start with a specifier.
            if index == 0 && specifier.start() != 0 {
                split_string.push(T::from(format_string[..specifier.start()].to_string()));
            } else if index > 0 {
                // Create a domain for the substring between two specifiers.
                split_string.push(T::from(
                    format_string[last_end_index + 1..specifier.start()].to_string(),
                ));
            }

            self.insert_datatype_dependent_domains(
                &mut split_string,
                specifier,
                pi_state,
                state,
                arg,
            );
            last_end_index = specifier.end();
        }

        // Return *Top* if no specifiers were detected and no constant insertions were made.
        // If constant insertions were made, it is assumed that no more specifiers remain in the format string.
        // Meaning, that all specifiers were replaced with constants.
        if last_end_index == 0 {
            if constants_inserted {
                return T::from(format_string);
            } else {
                return T::create_top_value_domain();
            }
        }

        // Create a domain for the substring after the last specifier if the string does not end on a specifier.
        if last_end_index < format_string.len() - 1 {
            split_string.push(T::from(format_string[last_end_index + 1..].to_string()));
        }

        let mut complete_domain = split_string.first().unwrap().clone();
        split_string.remove(0);
        for domain in split_string.into_iter() {
            complete_domain = complete_domain.append_string_domain(&domain);
        }

        complete_domain
    }

    /// Inserts domains dependent on the data type represented by the format specifier.
    /// If the specifier represents a string, it is checked whether further string domains
    /// for the particular string are tracked.
    pub fn insert_datatype_dependent_domains(
        &self,
        split_string: &mut Vec<T>,
        specifier: Match,
        pi_state: &PointerInferenceState,
        state: &State<T>,
        arg: Arg,
    ) {
        if matches!(
            Datatype::from(specifier.as_str()[1..].to_string()),
            Datatype::Pointer
        ) {
            if let Ok(DataDomain::Pointer(pointer)) = pi_state.eval_parameter_arg(
                &arg,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                split_string.push(Context::<T>::merge_domains_from_multiple_pointer_targets(
                    state, pi_state, &pointer,
                ));
            } else {
                split_string.push(T::create_top_value_domain());
            }
        } else {
            split_string.push(Context::<T>::approximate_string_domain_from_datatype(
                specifier.as_str()[1..].to_string(),
            ));
        }
    }

    /// Merges domains from multiple pointer targets. The merged domain serves as input to a format string.
    /// If one of the targets does not contain a domain or the offset of a stack target cannot be parsed,
    /// a *Top* value is returned as no assumption can be made about the input.
    pub fn merge_domains_from_multiple_pointer_targets(
        state: &State<T>,
        pi_state: &PointerInferenceState,
        pointer: &PointerDomain<IntervalDomain>,
    ) -> T {
        let mut domains: Vec<T> = Vec::new();
        for (target, offset) in pointer.targets().iter() {
            // Check the stack offset map if the target points to a stack position.
            if pi_state.caller_stack_ids.contains(target) || pi_state.stack_id == *target {
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

    /// Inserts constant strings, integers and floats into a given format string.
    pub fn insert_constant_values_into_format_string(
        &self,
        format_string: String,
        var_args: &mut Vec<Arg>,
        pi_state: &PointerInferenceState,
    ) -> String {
        let mut new_string = format_string.clone();
        let arg_iter = var_args.clone();
        let mut removal_counter = 0;
        for (index, arg) in arg_iter.iter().enumerate() {
            let old_string = new_string.clone();
            if let Ok(DataDomain::Value(value)) = pi_state.eval_parameter_arg(
                arg,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                match arg.get_data_type().unwrap() {
                    Datatype::Integer => {
                        new_string = Context::<T>::insert_constant_integer_into_format_string(
                            new_string, value,
                        );
                    }
                    Datatype::Pointer => {
                        new_string =
                            self.insert_constant_string_into_format_string(new_string, value);
                    }
                    Datatype::Char => {
                        new_string =
                            self.insert_constant_char_into_format_string(new_string, value);
                    }
                    _ => (),
                }
            }

            if old_string != new_string {
                var_args.remove(index - removal_counter);
                removal_counter += 1;
            }
        }

        new_string
    }

    /// Inserts an integer constant into the format string.
    pub fn insert_constant_integer_into_format_string(
        format_string: String,
        constant: IntervalDomain,
    ) -> String {
        let integer_pattern = Regex::new(r#"%\d{0,2}[d,i,u,o,p,x,X,hi,hd,hu]"#).unwrap();
        let mut new_string = format_string.clone();
        if let Ok(integer_value) = constant.try_to_bitvec() {
            if let Ok(integer) = integer_value.try_to_i64() {
                new_string = integer_pattern
                    .replace(&new_string, integer.to_string())
                    .to_string();
            }
        }

        new_string
    }

    /// Inserts a char constant into the format string.
    pub fn insert_constant_char_into_format_string(
        &self,
        format_string: String,
        constant: IntervalDomain,
    ) -> String {
        let char_pattern = Regex::new(r#"%\d{0,2}[c,C]"#).unwrap();
        let mut new_string = format_string.clone();
        if let Ok(Some(char_code)) = self.runtime_memory_image.read(
            &constant
                .try_to_bitvec()
                .expect("Could not translate interval address to bitvector."),
            self.project
                .datatype_properties
                .get_size_from_data_type(Datatype::Char),
        ) {
            if let Some(c_char) = Context::<T>::parse_bitvec_to_char(char_code) {
                new_string = char_pattern
                    .replace(&new_string, c_char.to_string())
                    .to_string();
            }
        } else if let Ok(char_code) = constant.try_to_bitvec() {
            if let Some(c_char) = Context::<T>::parse_bitvec_to_char(char_code.clone()) {
                new_string = char_pattern
                    .replace(&new_string, c_char.to_string())
                    .to_string();
            }
        }

        new_string
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
    pub fn insert_constant_string_into_format_string(
        &self,
        format_string: String,
        constant: IntervalDomain,
    ) -> String {
        let string_pattern = Regex::new(r#"%\d{0,2}[s,S]"#).unwrap();
        let mut new_string = format_string.clone();
        if let Ok(string) = self.runtime_memory_image.read_string_until_null_terminator(
            &constant
                .try_to_bitvec()
                .expect("Could not translate interval address to bitvector."),
        ) {
            new_string = string_pattern.replace(&new_string, string).to_string();
        }

        new_string
    }

    /// Handles the resulting string domain from strcat and strncat calls.
    /// The symbol call returns the pointer to the destination string in its return register.
    pub fn handle_strcat_and_strncat_calls(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
    ) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(return_arg) = extern_symbol.parameters.first() {
                if let Ok(DataDomain::Pointer(return_pointer)) = pi_state.eval_parameter_arg(
                    return_arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    let mut input_domain = T::create_top_value_domain();
                    let target_domain = Context::<T>::merge_domains_from_multiple_pointer_targets(
                        state,
                        pi_state,
                        &return_pointer,
                    );

                    if let Some(input_arg) = extern_symbol.parameters.get(1) {
                        if let Ok(input_value) = pi_state.eval_parameter_arg(
                            input_arg,
                            &self.project.stack_pointer_register,
                            self.runtime_memory_image,
                        ) {
                            // Check whether the second input string is in read only memory or on stack/heap.
                            match input_value {
                                DataDomain::Pointer(input_pointer) => {
                                    input_domain =
                                        Context::<T>::merge_domains_from_multiple_pointer_targets(
                                            state,
                                            pi_state,
                                            &input_pointer,
                                        );
                                }
                                DataDomain::Value(data) => {
                                    if let Ok(global_address) = data.try_to_bitvec() {
                                        if let Ok(input_string) = self
                                            .runtime_memory_image
                                            .read_string_until_null_terminator(&global_address)
                                        {
                                            input_domain = T::from(input_string.to_string());
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }

                    Context::add_new_string_abstract_domain(
                        &mut new_state,
                        pi_state,
                        &return_pointer,
                        target_domain.append_string_domain(&input_domain),
                    );

                    if let Ok(return_register) = extern_symbol.get_unique_return_register() {
                        new_state.add_new_variable_to_pointer_entry(
                            return_register.clone(),
                            return_pointer,
                        );
                    } else {
                        new_state.add_unassigned_return_pointer(return_pointer);
                    }
                }
            }
        }

        new_state
    }

    /// Deletes string entries in the heap to string map if the corresponding pointer is used
    /// to free memory space.
    pub fn handle_free(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();

        if let Some(dest_arg) = extern_symbol.parameters.first() {
            if let Some(pi_state) = state.get_pointer_inference_state() {
                if let Ok(DataDomain::Pointer(pointer)) = pi_state.eval_parameter_arg(
                    dest_arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    let heap_to_string_map = state.get_heap_to_string_map();
                    for (target, _) in pointer.targets().iter() {
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
mod tests;
