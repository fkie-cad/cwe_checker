use std::collections::HashMap;

use crate::prelude::*;

use anyhow::Error;
use itertools::izip;
use petgraph::graph::NodeIndex;

use crate::abstract_domain::{
    AbstractIdentifier, AbstractLocation, DataDomain, HasTop, IntervalDomain, PointerDomain,
    TryToBitvec,
};
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::intermediate_representation::{Arg, Bitvector, Datatype, Tid};
use crate::utils::arguments::{
    get_input_format_string, get_variable_parameters,
    parse_format_string_parameters,
};
use crate::{abstract_domain::AbstractDomain, intermediate_representation::ExternSymbol};

use super::super::state::State;
use super::Context;

impl<'a, T: AbstractDomain + HasTop + Eq + From<String>> Context<'a, T> {
    /// Returns an abstract id generated from a function parameter.
    pub fn get_abstract_id_for_function_parameter(
        &self,
        arg: &Arg,
        call_tid: &Tid,
    ) -> AbstractIdentifier {
        match arg {
            Arg::Register{var, ..} => {
                AbstractIdentifier::new(call_tid.clone(), AbstractLocation::from_var(var).unwrap())
            }
            Arg::Stack { offset, size, .. } => AbstractIdentifier::new(
                call_tid.clone(),
                AbstractLocation::from_stack(&self.project.stack_pointer_register, size, offset)
                    .unwrap(),
            ),
        }
    }

    /// The output of a string symbol is added to the map of abstract strings.
    /// If the symbol returns a format string, the string is approximated
    /// as good as possible by checking the input parameters.
    pub fn handle_string_symbol_calls(
        &self,
        extern_symbol: &ExternSymbol,
        source_node: &NodeIndex,
        state: &State<T>,
        call_tid: &Tid,
    ) -> State<T> {
        match extern_symbol.name.as_str() {
            "scanf" | "__isoc99_scanf" => self.handle_scanf_calls(state, extern_symbol, call_tid),
            "sscanf" | "__isoc99_sscanf" => {
                self.handle_sscanf_calls(state, extern_symbol, call_tid)
            }
            "sprintf" | "snprintf" => {
                self.handle_sprintf_and_snprintf_calls(state, extern_symbol, call_tid)
            }
            "strcat" | "strncat" => self.handle_strcat_and_strncat_calls(source_node, state),
            "printf" => self.handle_printf_calls(source_node, state),
            _ => panic!("Unexpected Extern Symbol."),
        }
    }

    /// Handles the detection of string parameters to scanf calls.
    /// Adds new string abstract domains to the current state.
    pub fn handle_scanf_calls(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
        call_tid: &Tid,
    ) -> State<T> {
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
                self.create_abstract_domain_entries_for_function_arguments(
                    pi_state,
                    &mut new_state,
                    call_tid,
                    return_values.into_iter().map(|arg| (arg, None)).collect(),
                );
            }
        }

        new_state
    }

    pub fn create_abstract_domain_entries_for_function_arguments(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State<T>,
        call_tid: &Tid,
        arg_to_value_map: HashMap<Arg, Option<String>>,
    ) {
        for (argument, value) in arg_to_value_map.into_iter() {
            let abstract_id = self.get_abstract_id_for_function_parameter(&argument, call_tid);
            match argument {
                Arg::Register{var, ..} => {
                    if let DataDomain::Pointer(pointer) = pi_state.get_register(&var) {
                        Context::add_new_string_abstract_domain(
                            state,
                            pi_state,
                            pointer,
                            abstract_id,
                            value,
                        );
                    }
                }
                Arg::Stack { .. } => {
                    if let Ok(DataDomain::Pointer(pointer)) = pi_state.eval_parameter_arg(
                        &argument,
                        &self.project.stack_pointer_register,
                        self.runtime_memory_image,
                    ) {
                        Context::add_new_string_abstract_domain(
                            state,
                            pi_state,
                            pointer,
                            abstract_id,
                            value,
                        );
                    }
                }
            }
        }
    }

    pub fn handle_sscanf_calls(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
        call_tid: &Tid,
    ) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(arg) = extern_symbol.parameters.get(0) {
                if let Ok(DataDomain::Value(address)) = pi_state.eval_parameter_arg(
                    arg,
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
                            self.create_abstract_domain_entries_for_function_arguments(
                                pi_state,
                                &mut new_state,
                                call_tid,
                                source_return_string_map,
                            );
                        }
                    }
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
        pointer: PointerDomain<IntervalDomain>,
        abstract_id: AbstractIdentifier,
        domain_input_string: Option<String>,
    ) {
        if pointer.targets().len() == 1 {
            let (target, offset) = pointer.targets().iter().next().unwrap();
            if *target == pi_state.stack_id {
                if let Some(string) = domain_input_string {
                    state.add_string_domain(abstract_id.clone(), string)
                } else {
                    state.add_string_top_value(abstract_id.clone());
                }
                state.add_new_offset_to_string_entry(offset.try_to_bitvec().unwrap(), abstract_id);
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
        call_tid: &Tid,
    ) -> State<T> {
        let mut new_state = state.clone();
        if let Some(return_arg) = extern_symbol.parameters.get(0) {
            if let Some(pi_state) = state.get_pointer_inference_state() {
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
                    let mut processed_string = input_format_string.clone();
                    if let Ok(var_args) = get_variable_parameters(
                        self.project,
                        pi_state,
                        extern_symbol,
                        &*self.format_string_index_map,
                        self.runtime_memory_image,
                    ) {
                        let input_strings =
                            self.get_string_constant_parameter_if_available(var_args, pi_state);
                        processed_string = Context::<T>::insert_string_constants_into_format_string(
                            input_format_string,
                            input_strings,
                        );
                    }

                    let abstract_id =
                        self.get_abstract_id_for_function_parameter(return_arg, call_tid);

                    let return_destination = self
                        .get_return_destination_from_first_input_parameter(pi_state, return_arg);

                    Context::add_new_string_abstract_domain(
                        &mut new_state,
                        pi_state,
                        return_destination,
                        abstract_id,
                        Some(processed_string),
                    );
                }
            }
        }

        new_state
    }

    pub fn strip_format_string() -> String {
        todo!()
    }

    /// Takes the first parameter of a string function that returns its target.
    pub fn get_return_destination_from_first_input_parameter(
        &self,
        pi_state: &PointerInferenceState,
        return_arg: &Arg,
    ) -> PointerDomain<IntervalDomain> {
        let return_destination = match return_arg {
            Arg::Register{var, ..} => pi_state.get_register(var),
            Arg::Stack { offset, .. } => DataDomain::Pointer(PointerDomain::new(
                pi_state.stack_id.clone(),
                IntervalDomain::from(Bitvector::from_i64(*offset)),
            )),
        };

        match return_destination {
            DataDomain::Pointer(pointer) => pointer,
            _ => panic!("Unexpected return value for string function call."),
        }
    }

    /// Takes parameters parsed from an input format string and checks
    /// whether they point to global string constants.
    /// If so, they are returned in a string vector.
    /// If not, the format string specifier is returned.
    pub fn get_string_constant_parameter_if_available(
        &self,
        var_args: Vec<Arg>,
        pi_state: &PointerInferenceState,
    ) -> Vec<String> {
        let mut string_constants: Vec<String> = Vec::new();
        for arg in var_args.iter() {
            if Context::<T>::is_string_arg(arg) {
                if let Ok(DataDomain::Value(address)) = pi_state.eval_parameter_arg(
                    arg,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                ) {
                    if let Ok(string) = self.runtime_memory_image.read_string_until_null_terminator(
                        &address
                            .try_to_bitvec()
                            .expect("Could not translate interval address to bitvector."),
                    ) {
                        string_constants.push(string.to_string());
                    } else {
                        string_constants.push("%s".to_string());
                    }
                } else {
                    string_constants.push("%s".to_string());
                }
            }
        }

        string_constants
    }

    /// Checks whether an argument is of type string.
    pub fn is_string_arg(arg: &Arg) -> bool {
        let data_type = match arg {
            Arg::Register {data_type, ..} => data_type.clone().unwrap(),
            Arg::Stack {data_type, ..} => data_type.clone().unwrap(),
        };

        match data_type {
            Datatype::Pointer => true,
            _ => false,
        }
    }

    pub fn insert_string_constants_into_format_string(
        format_string: String,
        input_strings: Vec<String>,
    ) -> String {
        let mut insert_strings = input_strings.clone();
        let parted: Vec<String> = format_string.split("%s").map(|s| s.to_string()).collect();
        insert_strings.resize_with(parted.len(), || "".to_string());
        let sub_string_pairs: Vec<(&String, &String)> =
            parted.iter().zip(insert_strings.iter()).collect();

        sub_string_pairs
            .into_iter()
            .map(|(origin, input)| origin.to_owned() + input)
            .collect::<Vec<String>>()
            .join("")
    }

    pub fn handle_strcat_and_strncat_calls(
        &self,
        source_node: &NodeIndex,
        state: &State<T>,
    ) -> State<T> {
        todo!()
    }

    pub fn handle_printf_calls(&self, source_node: &NodeIndex, state: &State<T>) -> State<T> {
        todo!()
    }
}

#[cfg(test)]
mod tests;
