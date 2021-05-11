use petgraph::graph::NodeIndex;
use regex::Regex;

use crate::{
    abstract_domain::{DataDomain, IntervalDomain, TryToBitvec},
    analysis::interprocedural_fixpoint_generic::NodeValue,
    intermediate_representation::{Arg, ByteSize, CallingConvention, ExternSymbol, Variable},
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
    /// If the string function has a variable amount of parameters, the fixed parameters are overwritten
    /// as they only represented the destination of the incoming variable parameters.
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
                if string_symbol.has_var_args {
                    parameters = self.get_variable_number_parameters(pi_state, string_symbol);
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
        format_string_index: usize,
    ) -> String {
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
    pub fn parse_format_string_parameters(&self, format_string: &str) -> Vec<(String, ByteSize)> {
        let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S])"#)
            .expect("No valid regex!");

        re.captures_iter(format_string)
            .map(|cap| {
                (
                    cap[1].to_string(),
                    self.map_format_specifier_to_bytesize(cap[1].to_string()),
                )
            })
            .collect()
    }

    /// Maps a given format specifier to the bytesize of its corresponding data type.
    pub fn map_format_specifier_to_bytesize(&self, specifier: String) -> ByteSize {
        if Context::is_integer(&specifier) {
            return self.project.datatype_properties.integer_size;
        }

        if Context::is_float(&specifier) {
            return self.project.datatype_properties.double_size;
        }

        if Context::is_pointer(&specifier) {
            return self.project.datatype_properties.pointer_size;
        }

        panic!("Unknown format specifier.")
    }

    /// Returns an argument vector of detected variable parameters if they are of type string.
    pub fn get_variable_number_parameters(
        &self,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
    ) -> Vec<Arg> {
        let format_string_index = match self
            .symbol_maps
            .format_string_index
            .get(&extern_symbol.name)
        {
            Some(index) => *index,
            None => panic!("External Symbol does not contain a format string parameter."),
        };
        let format_string =
            self.get_input_format_string(pi_state, extern_symbol, format_string_index);
        let parameters = self.parse_format_string_parameters(format_string.as_str());
        if parameters
            .iter()
            .any(|(specifier, _)| Context::is_string(specifier))
        {
            return self.calculate_parameter_locations(
                parameters,
                extern_symbol.get_calling_convention(self.project),
                format_string_index,
            );
        }

        vec![]
    }

    /// Calculates the register and stack positions of format string parameters.
    /// The parameters are then returned as an argument vector for later tainting.
    pub fn calculate_parameter_locations(
        &self,
        parameters: Vec<(String, ByteSize)>,
        calling_convention: &CallingConvention,
        format_string_index: usize,
    ) -> Vec<Arg> {
        let mut var_args: Vec<Arg> = Vec::new();
        // The number of the remaining integer argument registers are calculated
        // from the format string position since it is the last fixed argument.
        let mut integer_arg_register_count =
            calling_convention.integer_parameter_register.len() - (format_string_index + 1);
        let mut float_arg_register_count = calling_convention.float_parameter_register.len();
        let mut stack_offset: i64 = 0;

        for (type_name, size) in parameters.iter() {
            if Context::is_integer(type_name) || Context::is_pointer(type_name) {
                if integer_arg_register_count > 0 {
                    if Context::is_string(type_name) {
                        let register_name = calling_convention.integer_parameter_register
                            [calling_convention.integer_parameter_register.len()
                                - integer_arg_register_count]
                            .clone();
                        var_args.push(Context::create_string_register_arg(
                            self.project.get_pointer_bytesize(),
                            register_name,
                        ));
                    }
                    integer_arg_register_count -= 1;
                } else {
                    if Context::is_string(type_name) {
                        var_args.push(Context::create_string_stack_arg(*size, stack_offset));
                    }
                    stack_offset += u64::from(*size) as i64
                }
            } else if float_arg_register_count > 0 {
                float_arg_register_count -= 1;
            } else {
                stack_offset += u64::from(*size) as i64;
            }
        }

        var_args
    }

    /// Creates a string stack parameter given a size and stack offset.
    pub fn create_string_stack_arg(size: ByteSize, stack_offset: i64) -> Arg {
        Arg::Stack {
            offset: stack_offset,
            size,
        }
    }

    /// Creates a string register parameter given a register name.
    pub fn create_string_register_arg(size: ByteSize, register_name: String) -> Arg {
        Arg::Register(Variable {
            name: register_name,
            size,
            is_temp: false,
        })
    }

    /// Checks whether the format specifier is of type int.
    pub fn is_integer(specifier: &str) -> bool {
        matches!(specifier, "d" | "i" | "o" | "x" | "X" | "u" | "c" | "C")
    }

    /// Checks whether the format specifier is of type pointer.
    pub fn is_pointer(specifier: &str) -> bool {
        matches!(specifier, "s" | "S" | "n" | "p")
    }

    /// Checks whether the format specifier is of type float.
    pub fn is_float(specifier: &str) -> bool {
        matches!(specifier, "f" | "F" | "e" | "E" | "a" | "A" | "g" | "G")
    }

    /// Checks whether the format specifier is a string pointer
    /// or a string.
    pub fn is_string(specifier: &str) -> bool {
        matches!(specifier, "s" | "S")
    }
}

#[cfg(test)]
mod tests;
