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
    fn generate_return_values_for_call(
        &mut self,
        input_ids: &BTreeSet<AbstractIdentifier>,
        return_args: &[Arg],
        call_tid: &Tid,
    ) {
        // Fill every output register with a value that may point to any pointer-sized input ID
        // or to an output ID specific to the call and output register.
        let generic_pointer_size = self.stack_id.unwrap_register().size;
        let generic_output_relative_values: BTreeMap<AbstractIdentifier, BitvectorDomain> =
            input_ids
                .iter()
                .filter(|id| id.bytesize() == generic_pointer_size)
                .map(|id| (id.clone(), BitvectorDomain::new_top(generic_pointer_size)))
                .collect();
        let mut generic_output = DataDomain::new_top(generic_pointer_size);
        generic_output.set_relative_values(generic_output_relative_values);

        for output_arg in return_args {
            if let Arg::Register {
                expr: Expression::Var(var),
                data_type: _,
            } = output_arg
            {
                if var.size == generic_pointer_size {
                    let specific_target = DataDomain::from_target(
                        AbstractIdentifier::from_var(call_tid.clone(), var),
                        Bitvector::zero(var.size.into()).into(),
                    );
                    let output = generic_output.merge(&specific_target);
                    self.set_register(var, output);
                }
            }
        }
    }

    /// Return a list of parameter arguments and their associated object signatures for the current state.
    ///
    /// A register (or stack position with positive offset) is considered a parameter
    /// if any access to its value at function start is recorded in the corresponding object signature.
    pub fn get_params_of_current_function(&self) -> Vec<(Arg, AccessPattern)> {
        let mut params = Vec::new();
        for (id, access_pattern) in self.tracked_ids.iter() {
            if id.get_tid() == self.get_current_function_tid() {
                if let Ok(param_arg) = generate_param_arg_from_abstract_id(id) {
                    if access_pattern.is_accessed() {
                        params.push((param_arg, *access_pattern));
                    } else if matches!(id.get_location(), &AbstractLocation::Pointer { .. }) {
                        // This is a stack parameter.
                        // If it was only loaded into a register but otherwise not used, then the read-flag needs to be set.
                        let mut access_pattern = *access_pattern;
                        access_pattern.set_read_flag();
                        params.push((param_arg, access_pattern));
                    }
                }
            }
        }
        params
    }

    /// Return a list of all potential global memory addresses
    /// for which any type of access has been tracked by the current state.
    pub fn get_global_mem_params_of_current_function(&self) -> Vec<(u64, AccessPattern)> {
        let mut global_params = Vec::new();
        for (id, access_pattern) in self.tracked_ids.iter() {
            if id.get_tid() == self.get_current_function_tid() {
                match id.get_location() {
                    AbstractLocation::GlobalPointer(address, _)
                    | AbstractLocation::GlobalAddress { address, .. } => {
                        global_params.push((*address, *access_pattern));
                    }
                    AbstractLocation::Pointer(_, _) | AbstractLocation::Register(_) => (),
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
        params: &[(Arg, AccessPattern)],
        global_memory: &RuntimeMemoryImage,
    ) {
        for (parameter, call_access_pattern) in params {
            let param_value = self.eval_parameter_arg(parameter);
            let param_value = self.substitute_global_mem_address(param_value, global_memory);
            for (id, offset) in param_value.get_relative_values() {
                if let Some(object) = self.tracked_ids.get_mut(id) {
                    *object = object.merge(call_access_pattern);
                }
                if *id == self.stack_id && call_access_pattern.is_dereferenced() {
                    if let Ok(offset) = offset.try_to_bitvec() {
                        // We also have to dereference the stack pointer and set the access flags of the pointed-to value
                        let value = self.load_unsized_value_from_stack(offset.clone());
                        for id in value.referenced_ids() {
                            if let Some(object) = self.tracked_ids.get_mut(id) {
                                // Since we do not know whether the value itself was also dereferenced in the callee,
                                // we have to assume some unknown access to the value.
                                object.set_unknown_access_flags();
                            }
                        }
                    }
                    if call_access_pattern.is_mutably_dereferenced() {
                        // The stack value may have been overwritten by the call
                        if let Ok(offset) = offset.try_to_offset() {
                            self.stack.mark_interval_values_as_top(
                                offset,
                                offset,
                                ByteSize::new(1),
                            );
                        }
                    }
                }
            }
        }
    }

    /// If the given abstract ID represents a possible parameter of the current function
    /// then return an argument object corresponding to the parameter.
    pub fn get_arg_corresponding_to_id(&self, id: &AbstractIdentifier) -> Option<Arg> {
        if id.get_tid() == self.stack_id.get_tid() {
            generate_param_arg_from_abstract_id(id).ok()
        } else {
            None
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

/// Generate an argument representing the location in the given abstract ID.
/// If the location is a pointer, it is assumed that the pointer points to the stack.
/// Returns an error if the location contains a second level of indirection
/// or if the location is associated to global memory.
fn generate_param_arg_from_abstract_id(id: &AbstractIdentifier) -> Result<Arg, Error> {
    match id.get_location() {
        AbstractLocation::Register(var) => Ok(Arg::from_var(var.clone(), None)),
        AbstractLocation::Pointer(var, mem_location) => match mem_location {
            AbstractMemoryLocation::Location { offset, size } => Ok(Arg::Stack {
                address: Expression::Var(var.clone()).plus_const(*offset),
                size: *size,
                data_type: None,
            }),
            AbstractMemoryLocation::Pointer { .. } => {
                Err(anyhow!("Memory location is not a stack offset."))
            }
        },
        AbstractLocation::GlobalAddress { .. } | AbstractLocation::GlobalPointer(_, _) => {
            Err(anyhow!("Global values are not parameters."))
        }
    }
}
