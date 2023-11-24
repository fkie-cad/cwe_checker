use super::*;
use crate::abstract_domain::{
    AbstractDomain, AbstractIdentifier, AbstractLocation, BitvectorDomain, DataDomain,
    RegisterDomain as _, SizedDomain, TryToBitvec,
};
use crate::utils::arguments;
use crate::{
    analysis::{forward_interprocedural_fixpoint, graph::Graph},
    intermediate_representation::Project,
};

/// The context struct for the fixpoint algorithm.
pub struct Context<'a> {
    graph: &'a Graph<'a>,
    project: &'a Project,
    /// Parameter access patterns for stubbed extern symbols.
    param_access_stubs: BTreeMap<&'static str, Vec<AccessPattern>>,
    /// Assigns to the name of a stubbed variadic symbol the index of its format string parameter
    /// and the access pattern for all variadic parameters.
    stubbed_variadic_symbols: BTreeMap<&'static str, (usize, AccessPattern)>,
}

impl<'a> Context<'a> {
    /// Generate a new context object.
    pub fn new(project: &'a Project, graph: &'a Graph<'a>) -> Self {
        Context {
            graph,
            project,
            param_access_stubs: stubs::generate_param_access_stubs(),
            stubbed_variadic_symbols: stubs::get_stubbed_variadic_symbols(),
        }
    }

    /// Compute the return values of a call and return them (without adding them to the caller state).
    ///
    /// The `callee_state` is the state of the callee at the return site.
    /// Return values corresponding to callee parameters are expressed in the abstract IDs that are known to the caller.
    /// Additionally, each return value also contains one abstract ID specific to the call instruction and return register.
    /// This ID is used to track abstract location access patterns to the return value of the call in the caller.
    fn compute_return_values_of_call<'cconv>(
        &self,
        caller_state: &mut State,
        callee_state: &State,
        calling_convention: &'cconv CallingConvention,
        call: &Term<Jmp>,
    ) -> Vec<(&'cconv Variable, DataDomain<BitvectorDomain>)> {
        let mut return_value_list = Vec::new();
        for return_register in &calling_convention.integer_return_register {
            let return_value = self.compute_return_register_value_of_call(
                caller_state,
                callee_state,
                return_register,
                call,
            );
            return_value_list.push((return_register, return_value));
        }
        for return_expr in &calling_convention.float_return_register {
            for return_register in return_expr.input_vars() {
                let return_value = self.compute_return_register_value_of_call(
                    caller_state,
                    callee_state,
                    return_register,
                    call,
                );
                return_value_list.push((return_register, return_value));
            }
        }
        return_value_list
    }

    /// Compute the return value for the given register.
    ///
    /// The return value contains the IDs of all possible input IDs of the call that it may reference.
    /// Additionally, it also contains a call- and register-specific abstract ID,
    /// which can be used to track the access patterns of the return value
    /// independently of whether the return value only references caller values or not.
    fn compute_return_register_value_of_call(
        &self,
        caller_state: &mut State,
        callee_state: &State,
        return_register: &Variable,
        call: &Term<Jmp>,
    ) -> DataDomain<BitvectorDomain> {
        let callee_value = callee_state.get_register(return_register);
        let mut return_value: DataDomain<BitvectorDomain> =
            DataDomain::new_empty(return_register.size);

        // For every relative value in the callee we check whether it is relative a parameter to the callee.
        // If yes, we can compute it relative to the value of the parameter at the callsite and add the result to the return value.
        for (callee_id, callee_offset) in callee_value
            .get_relative_values()
            .iter()
            .filter(|(callee_id, _)| callee_id.get_tid() == callee_state.get_current_function_tid())
        {
            if matches!(
                callee_id.get_location(),
                AbstractLocation::GlobalAddress { .. } | AbstractLocation::GlobalPointer(_, _)
            ) {
                // Globals get the same ID as if the global pointer originated in the caller.
                let caller_global_id = AbstractIdentifier::new(
                    caller_state.get_current_function_tid().clone(),
                    callee_id.get_location().clone(),
                );
                caller_state.add_id_to_tracked_ids(&caller_global_id);
                let caller_global =
                    DataDomain::from_target(caller_global_id, callee_offset.clone());
                return_value = return_value.merge(&caller_global);
            } else {
                let param_value = caller_state.eval_param_location(
                    callee_id.get_location(),
                    &self.project.runtime_memory_image,
                );
                let param_value = caller_state
                    .substitute_global_mem_address(param_value, &self.project.runtime_memory_image);
                for (param_id, param_offset) in param_value.get_relative_values() {
                    let value = DataDomain::from_target(
                        param_id.clone(),
                        param_offset.clone() + callee_offset.clone(),
                    );
                    return_value = return_value.merge(&value);
                }
            }
        }
        // Also add an ID representing the return register (regardless of what was added before).
        // This ID is used to track abstract location access patterns in relation to the return value.
        let id = AbstractIdentifier::from_var(call.tid.clone(), return_register);
        let value =
            DataDomain::from_target(id, Bitvector::zero(return_register.size.into()).into());
        return_value = return_value.merge(&value);

        return_value
    }

    /// Handle a call to a specific extern symbol.
    /// If function stubs exist for the symbol, then these are used to compute the effect of the call.
    /// Else the [generic symbol handler](State::handle_generic_extern_symbol) is called.
    fn handle_extern_symbol_call(
        &self,
        state: &mut State,
        extern_symbol: &ExternSymbol,
        call_tid: &Tid,
    ) {
        let cconv = self.project.get_calling_convention(extern_symbol);
        if let Some(param_access_list) = self.param_access_stubs.get(extern_symbol.name.as_str()) {
            // Set access flags for parameter access
            for (param, access_pattern) in extern_symbol.parameters.iter().zip(param_access_list) {
                let param_value = state.eval_parameter_arg(param);
                let param_value = state
                    .substitute_global_mem_address(param_value, &self.project.runtime_memory_image);
                for id in param_value.get_relative_values().keys() {
                    state.merge_access_pattern_of_id(id, access_pattern);
                }
            }
            if self
                .stubbed_variadic_symbols
                .get(extern_symbol.name.as_str())
                .is_some()
                && self
                    .set_access_flags_for_variadic_parameters(state, extern_symbol)
                    .is_none()
            {
                self.set_access_flags_for_generic_variadic_parameters(state, extern_symbol);
            }
            let return_val = stubs::compute_return_value_for_stubbed_function(
                self.project,
                state,
                extern_symbol,
                call_tid,
            );
            state.clear_non_callee_saved_register(&cconv.callee_saved_register);
            state.set_register(&cconv.integer_return_register[0], return_val);
        } else {
            state.handle_generic_extern_symbol(
                call_tid,
                extern_symbol,
                cconv,
                &self.project.runtime_memory_image,
            );
        }
    }

    /// Merges the access patterns for all variadic parameters of the given symbol.
    ///
    /// This function can only handle stubbed symbols where the number of variadic parameters can be parsed from a format string.
    /// If the parsing of the variadic parameters failed for any reason
    /// (e.g. because the format string could not be statically determined)
    /// then this function does not modify any access patterns.
    ///
    /// If the variadic access pattern contains the mutable dereference flag
    /// then all variadic parameters are assumed to be pointers.
    fn set_access_flags_for_variadic_parameters(
        &self,
        state: &mut State,
        extern_symbol: &ExternSymbol,
    ) -> Option<()> {
        let (format_string_index, variadic_access_pattern) = self
            .stubbed_variadic_symbols
            .get(extern_symbol.name.as_str())?;
        let format_string_address =
            state.eval_parameter_arg(&extern_symbol.parameters[*format_string_index]); // TODO: potential problem: What if the address is now an abstract ID? And how do we handle format strings in writeable memory anyway?
        let format_string_address = state.substitute_global_mem_address(
            format_string_address,
            &self.project.runtime_memory_image,
        );
        let format_string_address = self.get_global_mem_address(&format_string_address)?;
        let format_string = arguments::parse_format_string_destination_and_return_content(
            format_string_address,
            &self.project.runtime_memory_image,
        )
        .ok()?;
        let mut format_string_params = arguments::parse_format_string_parameters(
            &format_string,
            &self.project.datatype_properties,
        )
        .ok()?;
        if variadic_access_pattern.is_mutably_dereferenced() {
            // All parameters are pointers to where values shall be written.
            format_string_params =
                vec![
                    (Datatype::Pointer, self.project.stack_pointer_register.size);
                    format_string_params.len()
                ];
        }
        let format_string_args = arguments::calculate_parameter_locations(
            format_string_params,
            extern_symbol,
            self.project,
        );
        for param in format_string_args {
            let param_value = state.eval_parameter_arg(&param);
            let param_value = state
                .substitute_global_mem_address(param_value, &self.project.runtime_memory_image);
            for id in param_value.get_relative_values().keys() {
                state.merge_access_pattern_of_id(id, variadic_access_pattern);
            }
        }
        Some(())
    }

    /// Sets access patterns for variadic parameters
    /// of a call to a variadic function with unknown number of variadic parameters.
    /// This function assumes that all remaining integer parameter registers of the corresponding calling convention
    /// are filled with variadic parameters,
    /// but no variadic parameters are supplied as stack parameters.
    fn set_access_flags_for_generic_variadic_parameters(
        &self,
        state: &mut State,
        extern_symbol: &ExternSymbol,
    ) {
        let (_, variadic_access_pattern) = self
            .stubbed_variadic_symbols
            .get(extern_symbol.name.as_str())
            .unwrap();
        let cconv = self.project.get_calling_convention(extern_symbol);
        if extern_symbol.parameters.len() < cconv.integer_parameter_register.len() {
            for index in [
                extern_symbol.parameters.len(),
                cconv.integer_parameter_register.len() - 1,
            ] {
                let param = state.get_register(&cconv.integer_parameter_register[index]);
                let param =
                    state.substitute_global_mem_address(param, &self.project.runtime_memory_image);
                for id in param.get_relative_values().keys() {
                    state.merge_access_pattern_of_id(id, variadic_access_pattern);
                }
            }
        }
    }

    /// If the given data is either an absolute value or a unique relative value, where the corresponding abstract ID denotes a global memory address,
    /// then return the resulting global memory address.
    /// If the resulting constant value does not denote a global address then `None` is returned.
    ///
    /// If the data may denote more than one value, then also return `None`.
    fn get_global_mem_address(&self, data: &DataDomain<BitvectorDomain>) -> Option<Bitvector> {
        if let Some((id, offset)) = data.get_if_unique_target() {
            // Check if the relative value is a global memory address (in writeable memory)
            if let AbstractLocation::GlobalAddress { address, size: _ } = id.get_location() {
                if let Ok(offset_bitvec) = offset.try_to_bitvec() {
                    let mut global_address = Bitvector::from_u64(*address)
                        .into_truncate(offset.bytesize())
                        .ok()?;
                    global_address += &offset_bitvec;
                    if self
                        .project
                        .runtime_memory_image
                        .is_global_memory_address(&global_address)
                    {
                        return Some(global_address);
                    }
                }
            }
        } else {
            // Global addresses in read-only memory are still handled as absolute values.
            let global_address = data
                .get_if_absolute_value()
                .map(|value| value.try_to_bitvec().ok())??;
            if self
                .project
                .runtime_memory_image
                .is_global_memory_address(&global_address)
            {
                return Some(global_address);
            }
        }
        None
    }

    /// Adjust the stack register after a call to a function.
    ///
    /// On x86, this removes the return address from the stack
    /// (other architectures pass the return address in a register, not on the stack).
    /// On other architectures the stack register retains the value it had before the call.
    /// Note that in some calling conventions the callee also clears function parameters from the stack.
    /// We do not detect and handle these cases yet.
    fn adjust_stack_register_on_return_from_call(
        &self,
        state_before_call: &State,
        new_state: &mut State,
    ) {
        let stack_register = &self.project.stack_pointer_register;
        let stack_pointer = state_before_call.get_register(stack_register);
        match self.project.cpu_architecture.as_str() {
            "x86" | "x86_32" | "x86_64" => {
                let offset = Bitvector::from_u64(stack_register.size.into())
                    .into_truncate(apint::BitWidth::from(stack_register.size))
                    .unwrap();
                new_state.set_register(
                    stack_register,
                    stack_pointer.bin_op(BinOpType::IntAdd, &offset.into()),
                );
            }
            _ => new_state.set_register(stack_register, stack_pointer),
        }
    }
}

impl<'a> forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    fn merge(&self, state_left: &State, state_right: &State) -> State {
        state_left.merge(state_right)
    }

    fn update_def(&self, state: &State, def: &Term<Def>) -> Option<State> {
        let mut new_state = state.clone();
        match &def.term {
            Def::Assign { var, value } => {
                new_state.set_read_flag_for_input_ids_of_expression(value);
                let value = new_state.substitute_global_mem_address(
                    state.eval(value),
                    &self.project.runtime_memory_image,
                );
                new_state.set_register(var, value);
            }
            Def::Load { var, address } => {
                new_state.set_deref_flag_for_pointer_inputs_of_expression(address);
                new_state.set_read_flag_for_input_ids_of_expression(address);
                let address = new_state.substitute_global_mem_address(
                    state.eval(address),
                    &self.project.runtime_memory_image,
                );
                new_state.set_deref_flag_for_contained_ids(&address);
                let value = new_state.load_value(
                    address,
                    var.size,
                    Some(&self.project.runtime_memory_image),
                );
                let value = new_state
                    .substitute_global_mem_address(value, &self.project.runtime_memory_image);
                new_state.track_contained_ids(&value);
                new_state.set_register(var, value);
            }
            Def::Store { address, value } => {
                new_state.set_mutable_deref_flag_for_pointer_inputs_of_expression(address);
                new_state.set_read_flag_for_input_ids_of_expression(address);
                let address = new_state.substitute_global_mem_address(
                    state.eval(address),
                    &self.project.runtime_memory_image,
                );
                new_state.set_deref_mut_flag_for_contained_ids(&address);
                if state.get_offset_if_exact_stack_pointer(&address).is_some() {
                    // Only flag inputs of non-trivial expressions as accessed to prevent flagging callee-saved registers as parameters.
                    // Sometimes parameter registers are callee-saved (for no apparent reason).
                    new_state.set_read_flag_for_input_ids_of_nontrivial_expression(value);
                } else {
                    new_state.set_read_flag_for_input_ids_of_expression(value);
                }
                let value = new_state.substitute_global_mem_address(
                    state.eval(value),
                    &self.project.runtime_memory_image,
                );
                new_state.write_value(address, value);
            }
        }
        Some(new_state)
    }

    fn update_jump(
        &self,
        state: &State,
        jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        let mut new_state = state.clone();
        match &jump.term {
            Jmp::BranchInd(address) | Jmp::Return(address) => {
                new_state.set_read_flag_for_input_ids_of_expression(address);
            }
            Jmp::CBranch { condition, .. } => {
                new_state.set_read_flag_for_input_ids_of_expression(condition);
            }
            _ => (),
        }
        Some(new_state)
    }

    fn update_call(
        &self,
        _state: &State,
        _call: &Term<Jmp>,
        _target: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        // No knowledge is transferred from the caller to the callee.
        None
    }

    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut new_state = state.clone();
        match &call.term {
            Jmp::CallInd { target, .. } => {
                new_state.set_read_flag_for_input_ids_of_expression(target);
                if let Some(cconv) = self.project.get_standard_calling_convention() {
                    new_state.handle_unknown_function_stub(
                        call,
                        cconv,
                        &self.project.runtime_memory_image,
                    );
                    self.adjust_stack_register_on_return_from_call(state, &mut new_state);
                    return Some(new_state);
                }
            }
            Jmp::Call { target, .. } => {
                if let Some(extern_symbol) = self.project.program.term.extern_symbols.get(target) {
                    self.handle_extern_symbol_call(&mut new_state, extern_symbol, &call.tid);
                    if !extern_symbol.no_return {
                        self.adjust_stack_register_on_return_from_call(state, &mut new_state);
                        return Some(new_state);
                    }
                } else if let Some(cconv) = self.project.get_standard_calling_convention() {
                    new_state.handle_unknown_function_stub(
                        call,
                        cconv,
                        &self.project.runtime_memory_image,
                    );
                    self.adjust_stack_register_on_return_from_call(state, &mut new_state);
                    return Some(new_state);
                }
            }
            _ => (),
        }
        // The call could not be properly handled or is a non-returning function, so we treat it as a dead end in the control flow graph.
        None
    }

    fn update_return(
        &self,
        state: Option<&State>,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        calling_convention_opt: &Option<String>,
    ) -> Option<State> {
        if state.is_none() || state_before_call.is_none() {
            return None;
        }
        let calling_convention = match self
            .project
            .get_specific_calling_convention(calling_convention_opt)
        {
            Some(cconv) => cconv,
            None => return None,
        };
        let state_before_call = state_before_call.unwrap();
        let callee_state = state.unwrap();
        let mut new_state = state_before_call.clone();
        // Merge parameter access patterns with the access patterns from the callee.
        let parameters = callee_state.get_params_of_current_function();
        new_state.merge_parameter_access(&parameters, &self.project.runtime_memory_image);
        // Compute values for return register (but do not add them to `new_state` yet)
        let return_value_list = self.compute_return_values_of_call(
            &mut new_state,
            callee_state,
            calling_convention,
            call_term,
        );
        // From now on the operations on new_state are allowed to modify register values.
        // Only retain callee-saved register from the caller register values.
        new_state.clear_non_callee_saved_register(&calling_convention.callee_saved_register);
        // Now we can insert the return values into the state
        for (var, value) in return_value_list {
            new_state.set_register(var, value);
        }
        self.adjust_stack_register_on_return_from_call(state_before_call, &mut new_state);
        Some(new_state)
    }

    fn specialize_conditional(
        &self,
        state: &State,
        condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<State> {
        let mut new_state = state.clone();
        new_state.set_read_flag_for_input_ids_of_expression(condition);
        Some(new_state)
    }
}

#[cfg(test)]
pub mod tests;
