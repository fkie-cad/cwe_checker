use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;

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

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug> Context<'a, T> {
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
                if !standard_cconv
                    .callee_saved_register
                    .contains(&register.name)
                {
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

    /// Handles the detection of string parameters to memcpy calls.
    pub fn handle_memcpy_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(return_arg) = extern_symbol.parameters.first() {
                if let Ok(DataDomain::Pointer(return_pointer)) = pi_state.eval_parameter_arg(
                    return_arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    if let Some(input_arg) = extern_symbol.parameters.get(1) {
                        if let Ok(input_value) = pi_state.eval_parameter_arg(
                            input_arg,
                            &self.project.stack_pointer_register,
                            self.runtime_memory_image,
                        ) {
                            match input_value {
                                DataDomain::Pointer(input_pointer) => {
                                    // If both pointer domains contain more than one target add Top values for all return pointer targets
                                    // as it is unknown which target is copied to which destination.
                                    if return_pointer.targets().len() > 1
                                        && input_pointer.targets().len() > 1
                                    {
                                        Context::<T>::add_new_string_abstract_domain(
                                            &mut new_state,
                                            pi_state,
                                            &return_pointer,
                                            T::create_top_value_domain(),
                                        );
                                    } else if input_pointer.targets().len() > 1 {
                                        let copied_domain = Context::<T>::merge_domains_from_multiple_pointer_targets(&new_state, pi_state, &input_pointer);
                                        Context::<T>::add_new_string_abstract_domain(
                                            &mut new_state,
                                            pi_state,
                                            &return_pointer,
                                            copied_domain,
                                        );
                                    } else {
                                        if let Some(copied_domain) = self
                                            .get_domain_from_single_pointer_target(
                                                &new_state,
                                                &input_pointer,
                                                pi_state,
                                            )
                                        {
                                            Context::<T>::add_new_string_abstract_domain(
                                                &mut new_state,
                                                pi_state,
                                                &return_pointer,
                                                copied_domain,
                                            );
                                        }
                                    }
                                }
                                DataDomain::Value(data) => {
                                    if let Ok(global_address) = data.try_to_bitvec() {
                                        if let Ok(input_string) = self
                                            .runtime_memory_image
                                            .read_string_until_null_terminator(&global_address)
                                        {
                                            new_state.add_unassigned_return_pointer(
                                                return_pointer.clone(),
                                            );
                                            println!("Return: {:?}", return_pointer);
                                            Context::<T>::add_new_string_abstract_domain(
                                                &mut new_state,
                                                pi_state,
                                                &return_pointer,
                                                T::from(input_string.to_string()),
                                            );
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
        }

        new_state
    }

    /// Returns a string domain for a single pointer target if there is one.
    /// Panics if the pointer has more than one target.
    pub fn get_domain_from_single_pointer_target(
        &self,
        state: &State<T>,
        pointer: &PointerDomain<IntervalDomain>,
        pi_state: &PointerInferenceState,
    ) -> Option<T> {
        if let Some((target, offset)) = pointer.unwrap_if_unique_target() {
            if pi_state.caller_stack_ids.contains(target) || pi_state.stack_id == *target {
                if let Ok(offset_value) = offset.try_to_offset() {
                    if let Some(domain) = state.get_stack_offset_to_string_map().get(&offset_value)
                    {
                        return Some(domain.clone());
                    }
                }
            } else {
                if let Some(domain) = state.get_heap_to_string_map().get(&target) {
                    return Some(domain.clone());
                }
            }
        } else {
            panic!(format!(
                "Unexpected number of pointer targets: {}; Should be 1",
                pointer.targets().len()
            ));
        }

        None
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

    /// Creates string abstract domains for return values of (s)scanf calls.
    pub fn create_abstract_domain_entries_for_function_return_values(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State<T>,
        arg_to_value_map: HashMap<Arg, Option<String>>,
    ) {
        for (argument, value) in arg_to_value_map.into_iter() {
            match argument.get_data_type().unwrap() {
                Datatype::Pointer => {
                    if let Ok(data) = pi_state.eval_parameter_arg(
                        &argument,
                        &self.project.stack_pointer_register,
                        self.runtime_memory_image,
                    ) {
                        if let DataDomain::Pointer(return_pointer) = data {
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
                _ => (),
            }
        }
    }

    /// Handles calls to sscanf. If the source string is known, it is split by spaces
    /// and for each substring a string abstract domain is generated at its corresponding location.
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

    /// Maps source strings parameters to return arguments for sscanf calls.
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
                            T::create_top_value_domain(),
                        );
                    }

                    new_state.add_unassigned_return_pointer(return_pointer);
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
        if Context::<T>::no_specifiers(input_format_string.clone()) {
            return T::from(input_format_string);
        }
        match get_variable_parameters(
            self.project,
            pi_state,
            extern_symbol,
            &*self.format_string_index_map,
            self.runtime_memory_image,
        ) {
            Ok(var_args) => {
                if var_args.is_empty() {
                    return T::create_top_value_domain();
                }

                self.create_string_domain_using_constants_and_sub_domains(
                    input_format_string,
                    &var_args,
                    pi_state,
                    state,
                )
            }
            Err(_) => self.create_string_domain_using_data_type_approximations(input_format_string),
        }
    }

    /// Creates a domain from a format string where all specifiers are approximated according
    /// to their data type. This ensures that, if there is a long data type, that the domain is
    /// no returned as *Top*.
    pub fn create_string_domain_using_data_type_approximations(&self, format_string: String) -> T {
        let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
            .expect("No valid regex!");

        let mut domains: Vec<T> = Vec::new();
        let mut last_specifier_end = 0;
        for (index, specifier) in re.find_iter(&format_string).enumerate() {
            if index == 0 {
                if specifier.start() > 0 {
                    domains.push(T::from(format_string[..specifier.start()].to_string()));
                }
            } else {
                let between_specifiers =
                    format_string[last_specifier_end..specifier.start()].to_string();
                if between_specifiers != "" {
                    domains.push(T::from(
                        format_string[last_specifier_end..specifier.start()].to_string(),
                    ));
                }
            }

            let parsed_specifier = specifier
                .as_str()
                .trim_start_matches(&['%', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'][..])
                .to_string();

            domains.push(Context::<T>::approximate_string_domain_from_datatype(
                parsed_specifier,
            ));

            last_specifier_end = specifier.end();
        }

        if last_specifier_end != format_string.len() {
            domains.push(T::from(format_string[last_specifier_end..].to_string()));
        }

        let mut init_domain = domains.first().unwrap().clone();
        domains.remove(0);
        for remaining_domain in domains.iter() {
            init_domain = init_domain.append_string_domain(remaining_domain);
        }

        init_domain
    }

    /// Checks whether the string has no format specifiers.
    pub fn no_specifiers(format_string: String) -> bool {
        let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
            .expect("No valid regex!");

        !re.is_match(&format_string)
    }

    /// Creates a string domain from found constants and sub domains.
    pub fn create_string_domain_using_constants_and_sub_domains(
        &self,
        format_string: String,
        var_args: &Vec<Arg>,
        pi_state: &PointerInferenceState,
        state: &State<T>,
    ) -> T {
        let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
            .expect("No valid regex!");
        let mut domains: Vec<T> = Vec::new();
        let mut last_specifier_end = 0;
        for (index, (specifier, arg)) in re
            .find_iter(&format_string.clone())
            .zip(var_args)
            .enumerate()
        {
            if index == 0 {
                if specifier.start() > 0 {
                    domains.push(T::from(format_string[..specifier.start()].to_string()));
                }
            } else {
                let between_specifiers =
                    format_string[last_specifier_end..specifier.start()].to_string();
                if between_specifiers != "" {
                    domains.push(T::from(
                        format_string[last_specifier_end..specifier.start()].to_string(),
                    ));
                }
            }
            domains.push(self.fetch_constant_or_domain_for_format_specifier(
                arg,
                specifier.as_str().to_string(),
                pi_state,
                state,
            ));
            last_specifier_end = specifier.end();
        }

        if last_specifier_end != format_string.len() {
            domains.push(T::from(format_string[last_specifier_end..].to_string()));
        }

        let mut init_domain = domains.first().unwrap().clone();
        domains.remove(0);
        for remaining_domain in domains.iter() {
            init_domain = init_domain.append_string_domain(remaining_domain);
        }

        init_domain
    }

    /// Tries to fetch a constant or sub domain for the format specifier.
    /// If no data is available, it approximates the sub domain corresponding to
    /// the characters that can be contained in the data type.
    pub fn fetch_constant_or_domain_for_format_specifier(
        &self,
        arg: &Arg,
        specifier: String,
        pi_state: &PointerInferenceState,
        state: &State<T>,
    ) -> T {
        if let Ok(data) = pi_state.eval_parameter_arg(
            arg,
            &self.project.stack_pointer_register,
            self.runtime_memory_image,
        ) {
            match data {
                DataDomain::Value(value) => {
                    if let Ok(value_vector) = value.try_to_bitvec() {
                        if let Some(data_type) = arg.get_data_type() {
                            match data_type {
                                Datatype::Char => {
                                    if let Some(char_domain) =
                                        self.get_constant_char_domain(value_vector)
                                    {
                                        return char_domain;
                                    }
                                }
                                Datatype::Integer => {
                                    if let Some(integer_domain) =
                                        Context::<T>::get_constant_integer_domain(value_vector)
                                    {
                                        return integer_domain;
                                    }
                                }
                                Datatype::Pointer => {
                                    if let Some(string_domain) =
                                        self.get_constant_string_domain(value_vector)
                                    {
                                        return string_domain;
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
                DataDomain::Pointer(pointer) => {
                    if let Some(data_type) = arg.get_data_type() {
                        if matches!(data_type, Datatype::Pointer) {
                            return Context::<T>::merge_domains_from_multiple_pointer_targets(
                                state, pi_state, &pointer,
                            );
                        }
                    }
                }
                DataDomain::Top(_) => (),
            }
        }

        let parsed_specifier = specifier
            .as_str()
            .trim_start_matches(&['%', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'][..])
            .to_string();

        Context::<T>::approximate_string_domain_from_datatype(parsed_specifier)
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
        if let Ok(Some(char_code)) = self.runtime_memory_image.read(
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
            .runtime_memory_image
            .read_string_until_null_terminator(&constant)
        {
            if string != "" {
                return Some(T::from(string.to_string()));
            }
        }

        None
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
                            DataDomain::Pointer(return_pointer),
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
