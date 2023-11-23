use super::*;

impl State {
    /// Handle a call to an extern symbol.
    ///
    /// Marks every possible input ID as accessed and writes to every return register a value
    /// that may point to any of the input IDs.
    pub fn handle_generic_extern_symbol(
        &mut self,
        call_tid: &Tid,
        extern_symbol: &ExternSymbol,
        calling_convention: &CallingConvention,
        global_memory: &RuntimeMemoryImage,
    ) {
        let input_ids = self.collect_input_ids_of_call(&extern_symbol.parameters, global_memory);
        self.clear_non_callee_saved_register(&calling_convention.callee_saved_register);
        self.generate_return_values_for_call(&input_ids, &extern_symbol.return_values, call_tid);
    }

    /// Handle a call to a completely unknown function
    /// by assuming that every input register of the given calling convention is an input
    /// and every integer return register of the calling convention is an output.
    ///
    /// Marks every possible input ID as accessed and writes to every return register a value
    /// that may point to any of the input IDs.
    pub fn handle_unknown_function_stub(
        &mut self,
        call: &Term<Jmp>,
        calling_convention: &CallingConvention,
        global_memory: &RuntimeMemoryImage,
    ) {
        let mut parameters =
            generate_args_from_registers(&calling_convention.integer_parameter_register);
        for float_param in &calling_convention.float_parameter_register {
            parameters.push(Arg::Register {
                expr: float_param.clone(),
                data_type: None,
            });
        }
        let mut return_register =
            generate_args_from_registers(&calling_convention.integer_return_register);
        for float_return_register in &calling_convention.float_return_register {
            return_register.push(Arg::Register {
                expr: float_return_register.clone(),
                data_type: None,
            });
        }
        let input_ids = self.collect_input_ids_of_call(&parameters, global_memory);
        self.clear_non_callee_saved_register(&calling_convention.callee_saved_register);
        self.generate_return_values_for_call(&input_ids, &return_register, &call.tid);
    }

    /// Get all input IDs referenced in the parameters of a call.
    /// Marks every input ID as accessed (with access flags for unknown access).
    /// Also generates stack parameter IDs and global memory IDs for the current function if necessary.
    fn collect_input_ids_of_call(
        &mut self,
        parameters: &[Arg],
        global_memory: &RuntimeMemoryImage,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut input_ids = BTreeSet::new();
        for input_param in parameters {
            let param = self.eval_parameter_arg(input_param);
            let param = self.substitute_global_mem_address(param, global_memory);
            for (id, offset) in param.get_relative_values() {
                input_ids.insert(id.clone());
                // If the relative value points to the stack we also have to collect all IDs contained in the pointed-to value.
                if *id == self.stack_id {
                    if let Ok(offset) = offset.try_to_bitvec() {
                        let value = self.load_unsized_value_from_stack(offset);
                        for id in value.get_relative_values().keys() {
                            input_ids.insert(id.clone());
                        }
                    }
                }
            }
        }
        // Mark every input ID as accessed
        for id in &input_ids {
            if let Some(object) = self.tracked_ids.get_mut(id) {
                object.set_unknown_access_flags();
            }
        }
        input_ids
    }

    /// Delete the content of all non-callee-saved registers from the state.
    pub fn clear_non_callee_saved_register(&mut self, callee_saved: &[Variable]) {
        self.register.retain(|var, _| callee_saved.contains(var));
    }

    /// Fill every return register that might be a pointer with a value that may point to any pointer-sized input ID
    /// or to an output ID specific to the call and output register.
    /// Non-pointer-sized output registers are only filled with an ID specific to the call and output register.
    fn generate_return_values_for_call(
        &mut self,
        input_ids: &BTreeSet<AbstractIdentifier>,
        return_args: &[Arg],
        call_tid: &Tid,
    ) {
        let generic_pointer_size = self.stack_id.bytesize();
        let generic_output_relative_values: BTreeMap<AbstractIdentifier, BitvectorDomain> =
            input_ids
                .iter()
                .filter(|id| id.bytesize() == generic_pointer_size)
                .map(|id| (id.clone(), BitvectorDomain::new_top(generic_pointer_size)))
                .collect();
        let mut generic_output = DataDomain::new_empty(generic_pointer_size);
        generic_output.set_relative_values(generic_output_relative_values);

        for output_arg in return_args {
            if let Arg::Register {
                expr: Expression::Var(var),
                data_type: _,
            } = output_arg
            {
                let specific_id = AbstractIdentifier::from_var(call_tid.clone(), var);
                self.add_id_to_tracked_ids(&specific_id);
                let specific_target =
                    DataDomain::from_target(specific_id, Bitvector::zero(var.size.into()).into());
                if var.size == generic_pointer_size {
                    let output = generic_output.merge(&specific_target);
                    self.set_register(var, output);
                } else {
                    self.set_register(var, specific_target);
                }
            }
        }
    }

    /// Return a list of parameter arguments and their associated object signatures for the current state.
    ///
    /// A register (or stack position with positive offset) is considered a parameter
    /// if any access to its value at function start is recorded in the corresponding object signature.
    pub fn get_params_of_current_function(&self) -> Vec<(&AbstractLocation, AccessPattern)> {
        let mut params = Vec::new();
        for (id, access_pattern) in self.tracked_ids.iter() {
            if id.get_tid() == self.get_current_function_tid()
                && !matches!(
                    id.get_location(),
                    AbstractLocation::GlobalAddress { .. } | AbstractLocation::GlobalPointer(_, _)
                )
            {
                if access_pattern.is_accessed() {
                    params.push((id.get_location(), *access_pattern));
                } else if matches!(id.get_location(), &AbstractLocation::Pointer { .. }) {
                    // The address of the parameter was explicitly used, despite the parameter not being directly accessed.
                    // We set the read flag to indicate that the parameter is relevant in some (unknown) way.
                    let mut access_pattern = *access_pattern;
                    access_pattern.set_read_flag();
                    params.push((id.get_location(), access_pattern));
                }
            }
        }
        params
    }

    /// Return a list of all potential global memory addresses
    /// for which any type of access has been tracked by the current state.
    pub fn get_global_mem_params_of_current_function(
        &self,
    ) -> Vec<(&AbstractLocation, AccessPattern)> {
        let mut global_params = Vec::new();
        for (id, access_pattern) in self.tracked_ids.iter() {
            if id.get_tid() == self.get_current_function_tid() {
                let location = id.get_location();
                if matches!(
                    location,
                    AbstractLocation::GlobalAddress { .. } | AbstractLocation::GlobalPointer(_, _)
                ) {
                    global_params.push((location, *access_pattern));
                }
            }
        }
        global_params
    }

    /// Merges the access patterns of callee parameters with those of the caller (represented by `self`).
    /// The result represents the access patterns after returning to the caller and is written to `self`.
    ///
    /// If a parameter is a pointer to the stack frame of self, it is dereferenced
    /// to set the access patterns of the target.
    /// Note that this may create new stack parameter objects for self.
    pub fn merge_parameter_access(
        &mut self,
        params: &[(&AbstractLocation, AccessPattern)],
        global_memory: &RuntimeMemoryImage,
    ) {
        for (parameter, call_access_pattern) in params {
            let param_value = self.eval_param_location(parameter, global_memory);
            let param_value = self.substitute_global_mem_address(param_value, global_memory);

            for (id, offset) in param_value.get_relative_values() {
                if let Some(object) = self.tracked_ids.get_mut(id) {
                    *object = object.merge(call_access_pattern);
                } else if *id == self.stack_id {
                    // Add stack IDs only if they correspond to stack parameters, i.e. the offset is positive.
                    if let Ok(concrete_offset) = offset.try_to_bitvec() {
                        if !concrete_offset.sign_bit().to_bool() {
                            if let Some(stack_param) = self.generate_stack_param_id_if_nonexistent(
                                concrete_offset,
                                id.bytesize(),
                            ) {
                                let object = self.tracked_ids.get_mut(&stack_param).unwrap();
                                *object = object.merge(call_access_pattern);
                            }
                        }
                    }
                } else {
                    self.tracked_ids.insert(id.clone(), *call_access_pattern);
                }

                if *id == self.stack_id && call_access_pattern.is_mutably_dereferenced() {
                    // The stack value may have been overwritten by the call
                    if let Ok(offset) = offset.try_to_offset() {
                        self.stack
                            .mark_interval_values_as_top(offset, offset, ByteSize::new(1));
                    }
                }
            }
        }
    }

    /// Evaluate the value of a parameter location from a call on the current state.
    ///
    /// This function panics for global parameters.
    pub fn eval_param_location(
        &mut self,
        param_location: &AbstractLocation,
        global_memory: &RuntimeMemoryImage,
    ) -> DataDomain<BitvectorDomain> {
        match param_location {
            AbstractLocation::GlobalAddress { .. } | AbstractLocation::GlobalPointer(_, _) => {
                panic!("Globals are not valid parameter locations.")
            }
            AbstractLocation::Register(var) => {
                let value = self.get_register(var);
                self.substitute_global_mem_address(value, global_memory)
            }
            AbstractLocation::Pointer(var, mem_location) => {
                if var == self.stack_id.unwrap_register() {
                    self.eval_stack_pointer_param_location(mem_location, global_memory)
                } else {
                    let value = self.get_register(var);
                    let value = self.substitute_global_mem_address(value, global_memory);
                    self.eval_mem_location_relative_value(value, mem_location)
                }
            }
        }
    }

    /// Evaluate the value of a parameter location relative to the stack pointer position in the current state.
    fn eval_stack_pointer_param_location(
        &mut self,
        mem_location: &AbstractMemoryLocation,
        global_memory: &RuntimeMemoryImage,
    ) -> DataDomain<BitvectorDomain> {
        let stack_register = self.stack_id.unwrap_register();
        match mem_location {
            AbstractMemoryLocation::Location { offset, size } => {
                if let Some(stack_offset) =
                    self.get_offset_if_exact_stack_pointer(&self.get_register(stack_register))
                {
                    let stack_offset = stack_offset
                        + &Bitvector::from_i64(*offset).into_sign_resize(self.stack_id.bytesize());
                    self.load_value_from_stack(stack_offset, *size)
                } else {
                    DataDomain::new_top(*size)
                }
            }
            AbstractMemoryLocation::Pointer {
                offset,
                target: inner_mem_location,
            } => {
                if let Some(stack_offset) =
                    self.get_offset_if_exact_stack_pointer(&self.get_register(stack_register))
                {
                    let stack_offset = stack_offset
                        + &Bitvector::from_i64(*offset).into_sign_resize(self.stack_id.bytesize());
                    let value = self.load_value_from_stack(stack_offset, self.stack_id.bytesize());
                    let value = self.substitute_global_mem_address(value, global_memory);
                    self.eval_mem_location_relative_value(value, inner_mem_location)
                } else {
                    DataDomain::new_top(inner_mem_location.bytesize())
                }
            }
        }
    }
}

/// Generate register arguments from a list of registers.
fn generate_args_from_registers(registers: &[Variable]) -> Vec<Arg> {
    registers
        .iter()
        .map(|var| Arg::from_var(var.clone(), None))
        .collect()
}

#[cfg(test)]
pub mod tests;
