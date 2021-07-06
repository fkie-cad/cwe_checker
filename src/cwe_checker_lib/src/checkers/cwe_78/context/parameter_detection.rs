use petgraph::graph::NodeIndex;

use crate::intermediate_representation::Arg;
use crate::{
    analysis::pointer_inference::State as PointerInferenceState, checkers::cwe_476::Taint,
};
use crate::{
    analysis::{
        backward_interprocedural_fixpoint::Context as _,
        interprocedural_fixpoint_generic::NodeValue,
    },
    intermediate_representation::ExternSymbol,
    utils::arguments,
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
        }
        if self.is_user_input_symbol(symbol) {
            return self.taint_user_input_symbol_parameters(state, symbol, call_source_node);
        }

        self.taint_other_extern_symbol_parameters(state, symbol, call_source_node)
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

    /// In case of a *scanf* call, all taints are removed and a warning is generated, as the input can be arbitrary.
    /// However, the format string is analysed to avoid false positives. (e.g. pure integer input
    /// does not trigger a cwe warning)
    /// In case of a *sscanf* call, the source string pointer parameter is tainted, if one of the tainted
    /// return values is a string.
    /// Since the format parameters of a (s)scanf call are also the return locations, the relevance of the
    /// call to the analysis is checked after the parameters have been parsed.
    /// If the parameter list is empty (no string parameters), the function call is of no relevance.
    /// Furthermore, if the parameter list contains elements but none of them points to a tainted memory position,
    /// the function call is of no relevance, too.
    pub fn taint_user_input_symbol_parameters(
        &self,
        state: &State,
        user_input_symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();
        new_state
            .remove_non_callee_saved_taint(user_input_symbol.get_calling_convention(self.project));

        if let Some(NodeValue::Value(pi_state)) = self
            .pointer_inference_results
            .get_node_value(call_source_node)
        {
            if let Ok(parameters) = arguments::get_variable_parameters(
                self.project,
                pi_state,
                user_input_symbol,
                &self.symbol_maps.format_string_index,
                self.runtime_memory_image,
            ) {
                if !parameters.is_empty() {
                    match user_input_symbol.name.as_str() {
                        "scanf" | "__isoc99_scanf" => self.process_scanf(
                            call_source_node,
                            &mut new_state,
                            pi_state,
                            parameters,
                        ),
                        "sscanf" | "__isoc99_sscanf" => {
                            let source_string_register =
                                user_input_symbol.parameters.get(0).unwrap();
                            self.process_sscanf(
                                &mut new_state,
                                pi_state,
                                parameters,
                                source_string_register,
                            )
                        }
                        _ => panic!("Invalid user input symbol."),
                    }
                }
            }
            // TODO: Log errors that came up during the parameter parsing.
        }
        new_state
    }

    /// This function iterates over the scanf string parameters and generates a CWE warning
    /// in case one of them points to a tainted memory position.
    /// If the call is relevant, all taints are deleted since we cannot determine anymore,
    /// where the whole input originates from.
    pub fn process_scanf(
        &self,
        call_source_node: NodeIndex,
        new_state: &mut State,
        pi_state: &PointerInferenceState,
        parameters: Vec<Arg>,
    ) {
        for param in parameters.iter() {
            if let Ok(address) = pi_state.eval_parameter_arg(
                param,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                if new_state.address_points_to_taint(address.clone(), pi_state) {
                    self.generate_cwe_warning(
                        &self
                            .get_graph()
                            .node_weight(call_source_node)
                            .unwrap()
                            .get_sub()
                            .term
                            .name,
                    );
                    new_state.remove_all_register_taints();
                    new_state.remove_all_memory_taints();
                    break;
                }
            }
        }
    }

    /// This function iterates over the sscanf string parameters and taints the source string in case one
    /// of the return parameters points to a tainted memory position.
    /// Note that the return parameters and the format string input parameters are the same.
    pub fn process_sscanf(
        &self,
        new_state: &mut State,
        pi_state: &PointerInferenceState,
        format_string_parameters: Vec<Arg>,
        source_string_parameter: &Arg,
    ) {
        let mut is_relevant = false;
        for param in format_string_parameters.iter() {
            if let Ok(address) = pi_state.eval_parameter_arg(
                param,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                // Remove the tainted memory region if the return parameter points to it.
                if new_state.address_points_to_taint(address.clone(), pi_state) {
                    is_relevant = true;
                    new_state.remove_mem_taint_at_target(&address);
                }
            }
        }

        if is_relevant {
            if let Ok(address) = pi_state.eval_parameter_arg(
                source_string_parameter,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ) {
                new_state.save_taint_to_memory(
                    &address,
                    Taint::Tainted(self.project.stack_pointer_register.size),
                );
            }
        }
    }

    /// Taints the parameters of a non string related extern symbol if it is relevant to the taint analysis.
    /// To determine whether the symbol is relevant, it is checked if either the arch's return registers are tainted
    pub fn taint_other_extern_symbol_parameters(
        &self,
        state: &State,
        symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();
        // Check whether the return register is tainted before the call
        // If so, taint the parameter registers and memory addresses of possible stack parameters
        let return_registers = arguments::get_return_registers_from_symbol(symbol);
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

    /// This function taints the registers and stack positions of the parameter pointers for string functions
    /// such as sprintf, snprintf, etc.
    /// The size parameter is ignored if available (e.g. snprintf, strncat etc.).
    /// If the string function has a variable amount of parameters, the fixed parameters are overwritten
    /// as they only represent the destination of the incoming variable parameters.
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
                    if let Ok(args) = arguments::get_variable_parameters(
                        self.project,
                        pi_state,
                        string_symbol,
                        &self.symbol_maps.format_string_index,
                        self.runtime_memory_image,
                    ) {
                        parameters = args;
                    } else {
                        // TODO: Log errors that came up during the parameter parsing.
                        parameters = vec![]
                    }
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
        symbol: &ExternSymbol,
        pi_state: &PointerInferenceState,
        state: &mut State,
    ) -> bool {
        if let Some(param) = symbol.parameters.get(0) {
            self.first_param_points_to_memory_taint(pi_state, state, param)
        } else {
            panic!("Missing parameters for string related function!");
        }
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
                Arg::Register { var, .. } => {
                    state.set_register_taint(var, Taint::Tainted(var.size))
                }
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
}

#[cfg(test)]
mod tests;
