use petgraph::graph::NodeIndex;
use regex::Regex;

use crate::{
    abstract_domain::{DataDomain, IntervalDomain, TryToBitvec},
    analysis::interprocedural_fixpoint_generic::NodeValue,
    intermediate_representation::{Arg, ExternSymbol},
};
use crate::{
    analysis::pointer_inference::State as PointerInferenceState, checkers::cwe_476::Taint,
};

use super::{Context, State};

impl<'a> Context<'a> {
    /// This function determines whether the taint procedure for string related, user input related,
    /// or other extern symbols is used based on the symbol's tid.
    pub fn taint_generic_extern_symbol_parameters(
        &self,
        state: &State,
        symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        if self.is_string_symbol(symbol) {
            return self.taint_extern_string_symbol_parameters(state, symbol, call_source_node);
        } else if self.is_user_input_symbol(symbol) {
            return self.taint_user_input_symbol_parameters(state, symbol);
        }

        self.taint_other_extern_symbol_parameters(state, call_source_node, symbol)
    }

    /// Checks whether the current symbol is a string symbol as defined in the symbol configuration.
    pub fn is_string_symbol(&self, symbol: &ExternSymbol) -> bool {
        self.symbol_maps
            .string_symbol_map
            .get(&symbol.tid)
            .is_some()
    }

    /// Checks whether the current symbol is a user input symbol as defined in the symbol configuration.
    pub fn is_user_input_symbol(&self, symbol: &ExternSymbol) -> bool {
        self.symbol_maps
            .user_input_symbol_map
            .get(&symbol.tid)
            .is_some()
    }

    /// Taints the parameters of a non string related extern symbol if it is relevant to the taint analysis.
    /// To determine whether the symbol is relevant, it is checked if either the arch's return register is tainted
    pub fn taint_other_extern_symbol_parameters(
        &self,
        state: &State,
        call_source_node: NodeIndex,
        symbol: &ExternSymbol,
    ) -> State {
        let mut new_state = state.clone();
        // Check whether the return register is tainted before the call
        // If so, taint the parameter registers and memory addresses of possible stack parameters
        let return_registers = Context::get_return_registers_from_symbol(symbol);
        if new_state.check_return_registers_for_taint(return_registers) {
            new_state.remove_non_callee_saved_taint(symbol.get_calling_convention(self.project));
            if let Some(NodeValue::Value(pi_state)) = self
                .pointer_inference_results
                .get_node_value(call_source_node)
            {
                self.taint_function_parameters(&mut new_state, pi_state, symbol.parameters.clone());
            }
        }

        new_state
    }

    /// Returns all return registers of a symbol as a vector of strings.
    fn get_return_registers_from_symbol(symbol: &ExternSymbol) -> Vec<String> {
        symbol
            .return_values
            .iter()
            .filter_map(|ret| match ret {
                Arg::Register(var) => Some(var.name.clone()),
                _ => None,
            })
            .collect::<Vec<String>>()
    }

    /// This function taints the registers and stack positions of the parameter pointers for string functions
    /// such as sprintf, snprintf, etc.
    /// The size parameter is ignored if available (e.g. snprintf, strncat etc.)
    pub fn taint_extern_string_symbol_parameters(
        &self,
        state: &State,
        string_symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();
        new_state.remove_non_callee_saved_taint(string_symbol.get_calling_convention(self.project));

        if let Some(NodeValue::Value(pi_state)) = self
            .pointer_inference_results
            .get_node_value(call_source_node)
        {
            if self.is_relevant_string_function_call(string_symbol, pi_state, &mut new_state) {
                let mut parameters = string_symbol.parameters.clone();
                if self.has_variable_number_of_parameters(string_symbol) {
                    parameters
                        .append(&mut self.get_variable_number_parameters(pi_state, string_symbol));
                }
                self.taint_function_parameters(&mut new_state, pi_state, parameters);
            }
        }
        new_state
    }

    /// Checks whether a string function call is a relevant call to the taint analysis.
    /// Since the first parameter of these string functions is also the return parameter,
    /// it is checked whether is points to a tainted memory address.
    pub fn is_relevant_string_function_call(
        &self,
        string_symbol: &ExternSymbol,
        pi_state: &PointerInferenceState,
        state: &mut State,
    ) -> bool {
        if let Some(param) = string_symbol.parameters.get(0) {
            self.first_param_points_to_memory_taint(pi_state, state, param)
        } else {
            panic!("Missing parameters for string related function!");
        }
    }

    /// Taints the input parameter of user input symbols.
    /// In case of a *scanf* call, no taint is added since the input can be arbitrary.
    /// However, the format string is analysed to avoid false positives. (e.g. pure integer input
    /// does not trigger a cwe warning)
    /// In case of a *sscanf* call, the source string pointer parameter is tainted, if one of the tainted
    /// return values is a string.
    pub fn taint_user_input_symbol_parameters(
        &self,
        state: &State,
        _user_input_symbol: &ExternSymbol,
    ) -> State {
        state.clone()
    }

    /// Taints register and stack function arguments.
    pub fn taint_function_parameters(
        &self,
        state: &mut State,
        pi_state: &PointerInferenceState,
        parameters: Vec<Arg>,
    ) {
        for parameter in parameters.iter() {
            match parameter {
                Arg::Register(var) => state.set_register_taint(var, Taint::Tainted(var.size)),
                Arg::Stack { size, .. } => {
                    if let Ok(address) = pi_state.eval_parameter_arg(
                        parameter,
                        &self.project.stack_pointer_register,
                        self.runtime_memory_image,
                    ) {
                        state.save_taint_to_memory(&address, Taint::Tainted(*size))
                    }
                }
            }
        }
    }

    /// Parses the input format string for the corresponding string function.
    pub fn get_input_format_string(
        &self,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
    ) -> String {
        let format_string_index = match extern_symbol.name.as_str() {
            "scanf" => 0,
            "sscanf" => 1,
            "sprintf" => 1,
            "snprintf" => 2,
            _ => panic!("Invalid function."),
        };

        if let Some(format_string) = extern_symbol.parameters.get(format_string_index) {
            if let Ok(address) = pi_state.eval_parameter_arg(
                format_string,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                self.parse_format_string_destination_and_return_content(address)
            } else {
                panic!("Could not parse target address of format string pointer.");
            }
        } else {
            panic!(
                "No format string parameter at specified index {} for function {}",
                format_string_index, extern_symbol.name
            );
        }
    }

    /// Parses the destiniation address of the format string.
    /// It checks whether the address points to another pointer in memory.
    /// If so, it will use the target address of that pointer read the format string from memory.
    pub fn parse_format_string_destination_and_return_content(
        &self,
        address: DataDomain<IntervalDomain>,
    ) -> String {
        if let Ok(address_vector) = address.try_to_bitvec() {
            let parsed_address = match self
                .runtime_memory_image
                .parse_address_if_recursive(&address_vector, self.project.get_pointer_bytesize())
            {
                Ok(addr) => addr,
                Err(e) => panic!("{}", e),
            };
            match self
                .runtime_memory_image
                .read_string_until_null_terminator(&parsed_address)
            {
                Ok(format_string) => format_string.to_string(),
                Err(e) => panic!("{}", e),
            }
        } else {
            panic!("Could not translate format string address to bitvector.");
        }
    }

    /// Parses the format string parameters using a regex, determines their data types,
    /// and calculates their positions (register or memory).
    pub fn _parse_format_string_parameters(&self, format_string: &str) -> Vec<String> {
        let re = Regex::new(r#"(%\d{0,2}[c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S,Z])"#)
            .expect("No valid regex!");

        re.captures_iter(format_string)
            .map(|cap| cap[0].to_string())
            .collect()
    }

    /// Determines whether a function has a variable number of parameters.
    pub fn has_variable_number_of_parameters(&self, extern_symbol: &ExternSymbol) -> bool {
        self.symbol_maps
            .variable_parameter_symbol_map
            .contains_key(&extern_symbol.tid)
    }

    /// Returns a vector of detected variable parameters.
    pub fn get_variable_number_parameters(
        &self,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
    ) -> Vec<Arg> {
        let var_args: Vec<Arg> = Vec::new();
        let _format_string = self.get_input_format_string(pi_state, extern_symbol);
        var_args
    }
}

#[cfg(test)]
mod tests;
