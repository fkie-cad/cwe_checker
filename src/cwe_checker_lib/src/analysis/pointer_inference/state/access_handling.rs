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

    /// Get the value of a register by its name.
    ///
    /// Returns None if no value is set for the register.
    pub fn get_register_by_name(&self, reg_name: &str) -> Option<Data> {
        self.register.iter().find_map(|(key, value)| {
            if key.name == reg_name {
                Some(value.clone())
            } else {
                None
            }
        })
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
                .map(|caller_stack_id| {
                    PointerDomain::new(caller_stack_id.clone(), offset.clone()).into()
                })
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
            match self.adjust_pointer_for_read(address) {
                Data::Pointer(pointer) => {
                    self.memory.set_value(pointer, value.clone())?;
                    Ok(())
                }
                Data::Value(absolute_address) => {
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
                }
                Data::Top(_) => Ok(()),
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
        match address {
            Data::Value(global_address) => {
                if let Ok(address_bitvector) = global_address.try_to_bitvec() {
                    if let Some(loaded_value) = global_memory.read(&address_bitvector, size)? {
                        Ok(Data::Value(loaded_value.into()))
                    } else {
                        Ok(Data::Top(size))
                    }
                } else if let Ok((start, end)) = global_address.try_to_offset_interval() {
                    if global_memory
                        .is_interval_readable(start as u64, end as u64 + u64::from(size))?
                    {
                        Ok(Data::new_top(size))
                    } else {
                        Err(anyhow!("Target address is not readable."))
                    }
                } else {
                    Ok(Data::new_top(size))
                }
            }
            Data::Top(_) => Ok(Data::new_top(size)),
            Data::Pointer(_) => Ok(self.memory.get_value(&address, size)?),
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
        if let Data::Pointer(pointer) = address {
            let mut new_targets = BTreeMap::new();
            for (id, offset) in pointer.targets() {
                if *id == self.stack_id {
                    if let Ok((interval_start, interval_end)) = offset.try_to_offset_interval() {
                        if interval_start >= 0
                            && interval_end >= 0
                            && !self.caller_stack_ids.is_empty()
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
            Data::Pointer(PointerDomain::with_targets(new_targets))
        } else {
            address.clone()
        }
    }

    /// Evaluate the value of an expression in the current state
    pub fn eval(&self, expression: &Expression) -> Data {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(&variable),
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
        stack_pointer: &Variable,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<Data, Error> {
        match parameter {
            Arg::Register { var, .. } => Ok(self.eval(&Expression::Var(var.clone()))),
            Arg::Stack { offset, size, .. } => self.load_value(
                &Expression::Var(stack_pointer.clone()).plus_const(*offset),
                *size,
                global_memory,
            ),
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
        let data = self.adjust_pointer_for_read(data);
        matches!(data, Data::Pointer(_))
            && self
                .memory
                .is_out_of_bounds_mem_access(&data, ByteSize::new(1), global_data)
    }

    /// Return `true` if `data` is a pointer to the current stack frame with a constant positive address,
    /// i.e. if it accesses a stack parameter (or the return-to address for x86) of the current function.
    pub fn is_stack_pointer_with_nonnegative_offset(&self, data: &Data) -> bool {
        if let Data::Pointer(pointer) = data {
            if pointer.targets().len() == 1 {
                let (target, offset) = pointer.targets().iter().next().unwrap();
                if *target == self.stack_id {
                    if let Ok(offset_val) = offset.try_to_offset() {
                        if offset_val >= 0 {
                            return true;
                        }
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
        if let Data::Pointer(pointer) = address {
            match (pointer.targets().len(), pointer.targets().iter().next()) {
                (1, Some((id, offset))) if self.stack_id == *id => {
                    if let Ok((interval_start, _interval_end)) = offset.try_to_offset_interval() {
                        if interval_start >= 0 {
                            return Some(offset.clone());
                        }
                    }
                }
                _ => (),
            }
        }
        None
    }
}
