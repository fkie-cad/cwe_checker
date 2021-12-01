//! Methods of [`State`] for handling memory and register access operations.

use crate::utils::binary::RuntimeMemoryImage;

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
        // If the address is a unique caller stack address, write to *all* caller stacks.
        if let Some(offset) = self.unwrap_offset_if_caller_stack_address(address) {
            let caller_addresses: Vec<_> = self
                .caller_stack_ids
                .iter()
                .map(|caller_stack_id| Data::from_target(caller_stack_id.clone(), offset.clone()))
                .collect();
            let mut result = Ok(());
            for address in caller_addresses {
                if let Err(err) = self.store_value(&address, &value.clone(), global_memory) {
                    result = Err(err);
                }
            }
            // Note that this only returns the last error that was detected.
            result
        } else {
            let pointer = self.adjust_pointer_for_read(address);
            self.memory.set_value(pointer.clone(), value.clone())?;
            if let Some(absolute_address) = pointer.get_absolute_value() {
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

    /// Evaluate the given load instruction and return the data read on success.
    pub fn load_value(
        &self,
        address: &Expression,
        size: ByteSize,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<Data, Error> {
        let address = self.adjust_pointer_for_read(&self.eval(address));
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
        result = result.merge(&self.memory.get_value(&address, size));

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
                self.set_register(var, data);
                Ok(())
            }
            Err(err) => {
                self.set_register(var, Data::new_top(var.size));
                Err(err)
            }
        }
    }

    /// If the pointer contains a reference to the stack with offset >= 0, replace it with a pointer
    /// pointing to all possible caller IDs.
    fn adjust_pointer_for_read(&self, address: &Data) -> Data {
        let mut adjusted_address = address.clone();
        let mut new_targets = BTreeMap::new();
        for (id, offset) in address.get_relative_values() {
            if *id == self.stack_id {
                if let Ok((interval_start, interval_end)) = offset.try_to_offset_interval() {
                    if interval_start >= 0 && interval_end >= 0 && !self.caller_stack_ids.is_empty()
                    {
                        for caller_id in self.caller_stack_ids.iter() {
                            new_targets.insert(caller_id.clone(), offset.clone());
                        }
                    // Note that the id of the current stack frame was *not* added.
                    } else {
                        new_targets.insert(id.clone(), offset.clone());
                    }
                } else {
                    for caller_id in self.caller_stack_ids.iter() {
                        new_targets.insert(caller_id.clone(), offset.clone());
                    }
                    // Note that we also add the id of the current stack frame
                    new_targets.insert(id.clone(), offset.clone());
                }
            } else {
                new_targets.insert(id.clone(), offset.clone());
            }
        }
        adjusted_address.set_relative_values(new_targets);
        adjusted_address
    }

    /// Evaluate the value of an expression in the current state
    pub fn eval(&self, expression: &Expression) -> Data {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(variable),
            Const(bitvector) => bitvector.clone().into(),
            BinOp { op, lhs, rhs } => {
                if *op == BinOpType::IntXOr && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Bitvector::zero(apint::BitWidth::from(lhs.bytesize())).into();
                }
                let (left, right) = (self.eval(lhs), self.eval(rhs));
                left.bin_op(*op, &right)
            }
            UnOp { op, arg } => self.eval(arg).un_op(*op),
            Cast { op, size, arg } => self.eval(arg).cast(*op, *size),
            Unknown {
                description: _,
                size,
            } => Data::new_top(*size),
            Subpiece {
                low_byte,
                size,
                arg,
            } => self.eval(arg).subpiece(*low_byte, *size),
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

    /// Check if an expression contains a use-after-free.
    /// If yes, mark the corresponding memory objects as flagged.
    pub fn contains_access_of_dangling_memory(&mut self, def: &Def) -> bool {
        match def {
            Def::Load { address, .. } | Def::Store { address, .. } => {
                let address_value = self.eval(address);
                if self.memory.is_dangling_pointer(&address_value, true) {
                    self.memory
                        .mark_dangling_pointer_targets_as_flagged(&address_value);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Returns `true` if the given `Def` is a load or store instruction
    /// which may access a memory object outside its bounds.
    pub fn contains_out_of_bounds_mem_access(
        &self,
        def: &Def,
        global_data: &RuntimeMemoryImage,
    ) -> bool {
        let (raw_address, size) = match def {
            Def::Load { address, var } => (self.eval(address), var.size),
            Def::Store { address, value } => (self.eval(address), value.bytesize()),
            _ => return false,
        };
        if self.is_stack_pointer_with_nonnegative_offset(&raw_address) {
            // Access to a parameter or the return address of the function
            return false;
        }
        let address = self.adjust_pointer_for_read(&raw_address);
        self.memory
            .is_out_of_bounds_mem_access(&address, size, global_data)
    }

    /// Returns `true` if `data` is a pointer pointing outside of the bounds of a memory buffer.
    /// Does not check whether `data` may represent an out-of-bounds access to global memory,
    /// since this function assumes that all absolute values are not pointers.
    pub fn pointer_contains_out_of_bounds_target(
        &self,
        data: &Data,
        global_data: &RuntimeMemoryImage,
    ) -> bool {
        let mut data = self.adjust_pointer_for_read(data);
        data.set_absolute_value(None); // Do not check absolute_values
        self.memory
            .is_out_of_bounds_mem_access(&data, ByteSize::new(1), global_data)
    }

    /// Return `true` if `data` is a pointer to the current stack frame with a constant positive address,
    /// i.e. if it accesses a stack parameter (or the return-to address for x86) of the current function.
    pub fn is_stack_pointer_with_nonnegative_offset(&self, data: &Data) -> bool {
        if let Some((target, offset)) = data.get_if_unique_target() {
            if *target == self.stack_id {
                if let Ok(offset_val) = offset.try_to_offset() {
                    if offset_val >= 0 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// If  the given address is a positive stack offset and `self.caller_stack_ids` is non-empty,
    /// i.e. it is an access to the caller stack, return the offset.
    ///
    /// In all other cases, including the case that the address has more than one target, return `None`.
    fn unwrap_offset_if_caller_stack_address(&self, address: &Data) -> Option<ValueDomain> {
        if self.caller_stack_ids.is_empty() {
            return None;
        }
        if let Some((id, offset)) = address.get_if_unique_target() {
            if self.stack_id == *id {
                if let Ok((interval_start, _interval_end)) = offset.try_to_offset_interval() {
                    if interval_start >= 0 {
                        return Some(offset.clone());
                    }
                }
            }
        }
        None
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
            .map(|val| val.try_to_offset_interval().ok())
            .flatten()
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
