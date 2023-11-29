//! Methods of [`State`] for handling memory and register access operations.

use super::*;

impl State {
    /// Get the value of a register or Top() if no value is known.
    pub fn get_register(&self, variable: &Variable) -> Data {
        if let Some(data) = self.register.get(variable) {
            data.clone()
        } else {
            Data::new_top(variable.size)
        }
    }

    /// Set the value of a register.
    pub fn set_register(&mut self, variable: &Variable, value: Data) {
        if !value.is_top() {
            self.register.insert(variable.clone(), value);
        } else {
            self.register.remove(variable);
        }
    }

    /// Evaluate expression on the given state and write the result to the target register.
    pub fn handle_register_assign(&mut self, target: &Variable, expression: &Expression) {
        self.set_register(target, self.eval(expression))
    }

    /// Store `value` at the given `address`.
    pub fn store_value(
        &mut self,
        address: &Data,
        value: &Data,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        self.memory.set_value(address.clone(), value.clone())?;
        if let Some(absolute_address) = address.get_absolute_value() {
            if let Ok(address_to_global_data) = absolute_address.try_to_bitvec() {
                match global_memory.is_address_writeable(&address_to_global_data) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(anyhow!("Write to read-only global data")),
                    Err(err) => Err(err),
                }
            } else if let Ok((start, end)) = absolute_address.try_to_offset_interval() {
                match global_memory.is_interval_writeable(start as u64, end as u64) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(anyhow!("Write to read-only global data")),
                    Err(err) => Err(err),
                }
            } else {
                // We assume inexactness of the algorithm instead of a possible CWE here.
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Write a value to the address one gets when evaluating the address expression.
    pub fn write_to_address(
        &mut self,
        address: &Expression,
        value: &Data,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        let address_data = self.eval(address);
        self.store_value(&address_data, value, global_memory)
    }

    /// Evaluate the store instruction, given by its address and value expressions,
    /// and modify the state accordingly.
    pub fn handle_store(
        &mut self,
        address: &Expression,
        value: &Expression,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        self.write_to_address(address, &self.eval(value), global_memory)
    }

    /// Evaluate the given address expression and return the data read from that address on success.
    pub fn load_value(
        &self,
        address: &Expression,
        size: ByteSize,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<Data, Error> {
        let address = self.eval(address);
        self.load_value_from_address(&address, size, global_memory)
    }

    /// Load the value at the given address from the state and return the data read on success.
    /// If the address contains more than one possible pointer target the results are merged for all possible pointer targets.
    pub fn load_value_from_address(
        &self,
        address: &Data,
        size: ByteSize,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<Data, Error> {
        let mut result = if let Some(global_address) = address.get_absolute_value() {
            if let Ok(address_bitvector) = global_address.try_to_bitvec() {
                match global_memory.read(&address_bitvector, size) {
                    Ok(Some(loaded_value)) => loaded_value.into(),
                    Ok(None) => Data::new_top(size),
                    Err(_) => Data::new_empty(size),
                }
            } else if let Ok((start, end)) = global_address.try_to_offset_interval() {
                if global_memory
                    .is_interval_readable(start as u64, end as u64 + u64::from(size))
                    .ok()
                    == Some(true)
                {
                    Data::new_top(size)
                } else {
                    Data::new_empty(size)
                }
            } else {
                Data::new_top(size)
            }
        } else {
            Data::new_empty(size)
        };
        result = result.merge(&self.memory.get_value(address, size));

        if let Ok(offset) = result.try_to_offset() {
            if result.bytesize() == self.stack_id.bytesize()
                && self.known_global_addresses.contains(&(offset as u64))
            {
                // The loaded value is most likely a pointer to a mutable global variable,
                // so we replace it with a pointer to the global memory object
                result = Data::from_target(
                    self.get_global_mem_id(),
                    result.try_to_bitvec().unwrap().into(),
                );
            }
        }

        if address.contains_top() {
            result.set_contains_top_flag()
        }
        if result.is_empty() {
            Err(anyhow!("Could not read from address"))
        } else {
            Ok(result)
        }
    }

    /// Handle a load instruction by assigning the value loaded from the address given by the `address` expression to `var`.
    pub fn handle_load(
        &mut self,
        var: &Variable,
        address: &Expression,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        match self.load_value(address, var.size, global_memory) {
            Ok(data) => {
                let data = self.replace_if_global_pointer(data);
                self.set_register(var, data);
                Ok(())
            }
            Err(err) => {
                self.set_register(var, Data::new_top(var.size));
                Err(err)
            }
        }
    }

    /// Evaluate the value of an expression in the current state.
    pub fn eval(&self, expression: &Expression) -> Data {
        let result = self.eval_recursive(expression);
        self.replace_if_global_pointer(result)
    }

    /// If the input value is a constant that is also the address of a global variable known to the function
    /// then replace it with a value relative to the global memory ID of the state.
    fn replace_if_global_pointer(&self, mut value: Data) -> Data {
        if let Ok(constant) = value.try_to_offset() {
            if self.known_global_addresses.contains(&(constant as u64)) {
                // The result is a constant that denotes a pointer to global writeable memory.
                // Thus we replace it with a value relative the global memory ID.
                value = Data::from_target(
                    self.get_global_mem_id(),
                    value.try_to_interval().unwrap().into(),
                );
            }
        }
        value
    }

    /// Recursively evaluate the value of an expression in the current state.
    /// Should only be called by [`State::eval`].
    fn eval_recursive(&self, expression: &Expression) -> Data {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(variable),
            Const(bitvector) => bitvector.clone().into(),
            BinOp { op, lhs, rhs } => {
                if *op == BinOpType::IntXOr && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Bitvector::zero(apint::BitWidth::from(lhs.bytesize())).into();
                }
                let (left, right) = (self.eval_recursive(lhs), self.eval_recursive(rhs));
                left.bin_op(*op, &right)
            }
            UnOp { op, arg } => self.eval_recursive(arg).un_op(*op),
            Cast { op, size, arg } => self.eval_recursive(arg).cast(*op, *size),
            Unknown {
                description: _,
                size,
            } => Data::new_top(*size),
            Subpiece {
                low_byte,
                size,
                arg,
            } => self.eval_recursive(arg).subpiece(*low_byte, *size),
        }
    }

    /// Evaluate the value of a parameter of an extern symbol for the given state.
    pub fn eval_parameter_arg(
        &self,
        parameter: &Arg,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<Data, Error> {
        match parameter {
            Arg::Register { expr, .. } => Ok(self.eval(expr)),
            Arg::Stack { address, size, .. } => self.load_value(address, *size, global_memory),
        }
    }

    /// Evaluate the value of the given abstract location on the current state.
    /// If the actual value cannot be determined (e.g. if an intermediate pointer returns `Top`)
    /// then a `Top` value is returned.
    pub fn eval_abstract_location(
        &self,
        location: &AbstractLocation,
        global_memory: &RuntimeMemoryImage,
    ) -> Data {
        match location {
            AbstractLocation::GlobalAddress { address, size } => {
                assert_eq!(*size, self.stack_id.bytesize());
                let pointer = Data::from_target(
                    self.get_global_mem_id().clone(),
                    Bitvector::from_u64(*address)
                        .into_resize_unsigned(self.stack_id.bytesize())
                        .into(),
                );
                pointer
            }
            AbstractLocation::GlobalPointer(address, nested_location) => {
                let pointer = Data::from_target(
                    self.get_global_mem_id().clone(),
                    Bitvector::from_u64(*address)
                        .into_resize_unsigned(self.stack_id.bytesize())
                        .into(),
                );
                self.eval_abstract_memory_location(nested_location, pointer, global_memory)
            }
            AbstractLocation::Register(var) => self.get_register(var),
            AbstractLocation::Pointer(var, nested_location) => {
                let pointer = self.get_register(var);
                self.eval_abstract_memory_location(nested_location, pointer, global_memory)
            }
        }
    }

    /// Evaluate the value of the given abstract memory location on the current state
    /// with the given `root_pointer` as the start point of the location description.
    fn eval_abstract_memory_location(
        &self,
        location: &AbstractMemoryLocation,
        root_pointer: Data,
        global_memory: &RuntimeMemoryImage,
    ) -> Data {
        match location {
            AbstractMemoryLocation::Location { offset, size } => {
                let pointer = root_pointer.add_offset(&Bitvector::from_i64(*offset).into());
                self.load_value_from_address(&pointer, *size, global_memory)
                    .unwrap_or_else(|_| Data::new_top(*size))
            }
            AbstractMemoryLocation::Pointer { offset, target } => {
                let pointer = root_pointer.add_offset(&Bitvector::from_i64(*offset).into());
                match self.load_value_from_address(
                    &pointer,
                    self.stack_id.bytesize(),
                    global_memory,
                ) {
                    Ok(nested_root_pointer) => self.eval_abstract_memory_location(
                        target,
                        nested_root_pointer,
                        global_memory,
                    ),
                    Err(_) => Data::new_top(location.bytesize()),
                }
            }
        }
    }

    /// Check whether the given `def` could result in a memory access through a NULL pointer.
    ///
    /// If no NULL pointer dereference is detected then `Ok(false)` is returned.
    /// If a NULL pointer dereference is detected,
    /// try to specialize the state so that `address_expr` cannot result in a NULL pointer anymore.
    /// If that succeeds, `Ok(true)` is returned.
    /// If that would result in an unsatisfiable state, an error is returned.
    pub fn check_def_for_null_dereferences(&mut self, def: &Term<Def>) -> Result<bool, Error> {
        let address_expr = match &def.term {
            Def::Load { address, .. } | Def::Store { address, .. } => address,
            Def::Assign { .. } => return Ok(false),
        };
        let mut address_val = self.eval(address_expr);
        if let Some((start_index, end_index)) = address_val
            .get_absolute_value()
            .and_then(|val| val.try_to_offset_interval().ok())
        {
            if (start_index > -1024 && start_index < 1024)
                || (end_index > -1024 && end_index < 1024)
            {
                // Interval starts or ends with a null pointer
                let absolute_val = address_val.get_absolute_value().unwrap().clone();
                let new_absolute_val = if start_index > -1024 && start_index < 1024 {
                    absolute_val
                        .add_signed_greater_equal_bound(
                            &Bitvector::from_i16(1024).into_resize_signed(address_val.bytesize()),
                        )
                        .ok()
                } else {
                    absolute_val
                        .add_signed_less_equal_bound(
                            &Bitvector::from_i16(-1024).into_resize_signed(address_val.bytesize()),
                        )
                        .ok()
                };
                address_val.set_absolute_value(new_absolute_val);
                if address_val.is_empty() {
                    return Err(anyhow!("Unsatisfiable state"));
                }
                self.specialize_by_expression_result(address_expr, address_val)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
