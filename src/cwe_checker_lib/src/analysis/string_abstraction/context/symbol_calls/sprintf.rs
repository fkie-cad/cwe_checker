use regex::Match;

use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::{
    abstract_domain::{
        AbstractDomain, DataDomain, DomainInsertion, HasTop, IntervalDomain, TryToBitvec,
    },
    analysis::string_abstraction::{context::Context, state::State},
    intermediate_representation::{Arg, Datatype, ExternSymbol},
    utils::arguments::{get_input_format_string, get_variable_parameters},
};

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
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
                if let Ok(return_pointer) =
                    pi_state.eval_parameter_arg(return_arg, self.runtime_memory_image)
                {
                    if !return_pointer.get_relative_values().is_empty() {
                        let format_string_index = self
                            .format_string_index_map
                            .get(&extern_symbol.name)
                            .unwrap();
                        self.parse_format_string_and_add_new_string_domain(
                            &mut new_state,
                            pi_state,
                            extern_symbol,
                            *format_string_index,
                            &return_pointer,
                        )
                    }

                    new_state.add_unassigned_return_pointer(return_pointer);
                }
            }
        }

        new_state
    }

    /// Gets the input format string, parses the input parameters and adds
    /// the generated domain to the string maps.
    pub fn parse_format_string_and_add_new_string_domain(
        &self,
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
        format_string_index: usize,
        return_pointer: &DataDomain<IntervalDomain>,
    ) {
        if let Ok(input_format_string) = get_input_format_string(
            pi_state,
            extern_symbol,
            format_string_index,
            self.runtime_memory_image,
        ) {
            let returned_abstract_domain = self.create_string_domain_for_sprintf_snprintf(
                pi_state,
                state,
                extern_symbol,
                input_format_string,
            );

            Context::<T>::add_new_string_abstract_domain(
                state,
                pi_state,
                return_pointer.get_relative_values(),
                returned_abstract_domain,
            );
        } else {
            Context::<T>::add_new_string_abstract_domain(
                state,
                pi_state,
                return_pointer.get_relative_values(),
                T::create_top_value_domain(),
            );
        }
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
            &self.format_string_index_map,
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
        let re = Context::<T>::re_format_specifier();
        let mut domains: Vec<T> = Vec::new();
        let mut last_specifier_end = 0;
        for (index, specifier) in re.find_iter(&format_string).enumerate() {
            Context::push_constant_subsequences_before_and_between_specifiers(
                &mut domains,
                &format_string,
                specifier,
                last_specifier_end,
                index,
            );

            Context::push_format_specifier_approximation(&mut domains, specifier);

            last_specifier_end = specifier.end();
        }

        Context::push_constant_suffix_if_available(
            &mut domains,
            &format_string,
            last_specifier_end,
        );

        Context::concat_domains(&mut domains)
    }

    /// Creates a string domain from found constants and sub domains.
    pub fn create_string_domain_using_constants_and_sub_domains(
        &self,
        format_string: String,
        var_args: &[Arg],
        pi_state: &PointerInferenceState,
        state: &State<T>,
    ) -> T {
        let re = Context::<T>::re_format_specifier();
        let mut domains: Vec<T> = Vec::new();
        let mut last_specifier_end = 0;
        for (index, (specifier, arg)) in re.find_iter(&format_string).zip(var_args).enumerate() {
            Context::push_constant_subsequences_before_and_between_specifiers(
                &mut domains,
                &format_string,
                specifier,
                last_specifier_end,
                index,
            );
            domains.push(self.fetch_constant_and_domain_for_format_specifier(
                arg,
                specifier.as_str().to_string(),
                pi_state,
                state,
            ));
            last_specifier_end = specifier.end();
        }

        Context::push_constant_suffix_if_available(
            &mut domains,
            &format_string,
            last_specifier_end,
        );

        Context::concat_domains(&mut domains)
    }

    /// Creates a string domain by approximating a format specifier and pushes it to the domain vector.
    pub fn push_format_specifier_approximation(domains: &mut Vec<T>, specifier: Match) {
        domains.push(Context::<T>::approximate_string_domain_from_datatype(
            Context::<T>::trim_format_specifier(specifier.as_str().to_string()),
        ));
    }

    /// Creates string domains from constant subsequences that either appear
    /// at the beginning of the format string or between specifiers.
    pub fn push_constant_subsequences_before_and_between_specifiers(
        domains: &mut Vec<T>,
        format_string: &str,
        specifier: Match,
        last_specifier_end: usize,
        index: usize,
    ) {
        if index == 0 {
            if specifier.start() > 0 {
                domains.push(T::from(format_string[..specifier.start()].to_string()));
            }
        } else {
            let between_specifiers =
                format_string[last_specifier_end..specifier.start()].to_string();
            if !between_specifiers.is_empty() {
                domains.push(T::from(
                    format_string[last_specifier_end..specifier.start()].to_string(),
                ));
            }
        }
    }

    /// Pushes a potential constant suffix to the string domain vector.
    pub fn push_constant_suffix_if_available(
        domains: &mut Vec<T>,
        format_string: &str,
        last_specifier_end: usize,
    ) {
        if last_specifier_end != format_string.len() {
            domains.push(T::from(format_string[last_specifier_end..].to_string()));
        }
    }

    /// Takes a vector of string domains and concatenates them.
    pub fn concat_domains(domains: &mut Vec<T>) -> T {
        let mut init_domain = domains.first().unwrap().clone();
        domains.remove(0);
        for remaining_domain in domains.iter() {
            init_domain = init_domain.append_string_domain(remaining_domain);
        }

        init_domain
    }

    /// Checks whether the string has no format specifiers.
    pub fn no_specifiers(format_string: String) -> bool {
        !Context::<T>::re_format_specifier().is_match(&format_string)
    }

    /// Tries to fetch a constant or sub domain for the format specifier.
    /// If no data is available, it approximates the sub domain corresponding to
    /// the characters that can be contained in the data type.
    pub fn fetch_constant_and_domain_for_format_specifier(
        &self,
        arg: &Arg,
        specifier: String,
        pi_state: &PointerInferenceState,
        state: &State<T>,
    ) -> T {
        if let Ok(data) = pi_state.eval_parameter_arg(arg, self.runtime_memory_image) {
            let constant_domain: Option<T> = self.fetch_constant_domain_if_available(&data, arg);
            if let Some(generated_domain) = Context::<T>::fetch_subdomains_if_available(
                &data,
                state,
                pi_state,
                arg,
                constant_domain.clone(),
            ) {
                return generated_domain;
            }

            if let Some(domain) = constant_domain {
                return domain;
            }
        }

        Context::<T>::approximate_string_domain_from_datatype(Context::<T>::trim_format_specifier(
            specifier,
        ))
    }

    /// Removes the '%' character and any size number from a format specifier.
    pub fn trim_format_specifier(specifier: String) -> String {
        specifier
            .as_str()
            .trim_start_matches(&['%', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'][..])
            .to_string()
    }

    /// Fetches subdomains if they are available for a pointer domain and merges a potential
    /// constant domain into the result.
    pub fn fetch_subdomains_if_available(
        data: &DataDomain<IntervalDomain>,
        state: &State<T>,
        pi_state: &PointerInferenceState,
        arg: &Arg,
        constant_domain: Option<T>,
    ) -> Option<T> {
        if !data.get_relative_values().is_empty() {
            if let Some(data_type) = arg.get_data_type() {
                if matches!(data_type, Datatype::Pointer) {
                    let mut generated_domain =
                        Context::<T>::merge_domains_from_multiple_pointer_targets(
                            state,
                            pi_state,
                            data.get_relative_values(),
                        );
                    if let Some(constant) = constant_domain {
                        generated_domain = generated_domain.merge(&constant);
                    }

                    return Some(generated_domain);
                }
            }
        }

        None
    }

    /// Takes a data domain and tries to get a constant value.
    pub fn fetch_constant_domain_if_available(
        &self,
        data: &DataDomain<IntervalDomain>,
        arg: &Arg,
    ) -> Option<T> {
        if let Some(value) = data.get_absolute_value() {
            if let Ok(value_vector) = value.try_to_bitvec() {
                if let Some(data_type) = arg.get_data_type() {
                    match data_type {
                        Datatype::Char => {
                            if let Some(char_domain) = self.get_constant_char_domain(value_vector) {
                                return Some(char_domain);
                            }
                        }
                        Datatype::Integer => {
                            if let Some(integer_domain) =
                                Context::<T>::get_constant_integer_domain(value_vector)
                            {
                                return Some(integer_domain);
                            }
                        }
                        Datatype::Pointer => {
                            if let Some(string_domain) =
                                self.get_constant_string_domain(value_vector)
                            {
                                return Some(string_domain);
                            }
                        }
                        _ => (),
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests;
