use super::*;

impl State {
    /// Get the value of a register or Top() if no value is known.
    ///
    /// Returns an error if the variable is not a register.
    pub fn get_register(&self, variable: &Variable) -> Result<Data, Error> {
        if let Some(data) = self.register.get(variable) {
            Ok(data.clone())
        } else {
            Ok(Data::new_top(variable.bitsize()?))
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
    ///
    /// Returns an error if the variable is not a register.
    pub fn set_register(&mut self, variable: &Variable, value: Data) -> Result<(), Error> {
        if let variable::Type::Immediate(_bitsize) = variable.type_ {
            if !value.is_top() {
                self.register.insert(variable.clone(), value);
            } else {
                self.register.remove(variable);
            }
            Ok(())
        } else {
            Err(anyhow!("Variable is not a register type"))
        }
    }

    /// Evaluate expression on the given state and write the result to the target register.
    pub fn handle_register_assign(
        &mut self,
        target: &Variable,
        expression: &Expression,
    ) -> Result<(), Error> {
        if let Expression::Var(variable) = expression {
            if target == variable {
                // The assign does nothing. Occurs as "do nothing"-path in conditional stores.
                // Needs special handling, since it is the only case where the target is allowed
                // to denote memory instead of a register.
                return Ok(());
            }
        }
        match self.eval(expression) {
            Ok(new_value) => {
                self.set_register(target, new_value)?;
                Ok(())
            }
            Err(err) => {
                self.set_register(target, Data::new_top(target.bitsize()?))?;
                Err(err)
            }
        }
    }

    /// Store `value` at the given `address`.
    pub fn store_value(&mut self, address: &Data, value: &Data) -> Result<(), Error> {
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
                if let Err(err) = self.store_value(&address, &value.clone()) {
                    result = Err(err);
                }
            }
            // Note that this only returns the last error that was detected.
            result
        } else if let Data::Pointer(pointer) = self.adjust_pointer_for_read(address) {
            self.memory.set_value(pointer, value.clone())?;
            Ok(())
        } else {
            // TODO: Implement recognition of stores to global memory.
            Err(anyhow!("Memory write to non-pointer data"))
        }
    }

    /// Write a value to the address one gets when evaluating the address expression.
    pub fn write_to_address(&mut self, address: &Expression, value: &Data) -> Result<(), Error> {
        match self.eval(address) {
            Ok(address_data) => self.store_value(&address_data, value),
            Err(err) => Err(err),
        }
    }

    /// Evaluate the given store expression on the given state and return the resulting state.
    ///
    /// The function panics if given anything else than a store expression.
    pub fn handle_store_exp(&mut self, store_exp: &Expression) -> Result<(), Error> {
        if let Expression::Store {
            memory: _,
            address,
            value,
            endian: _,
            size,
        } = store_exp
        {
            match self.eval(value) {
                Ok(data) => {
                    assert_eq!(data.bitsize(), *size);
                    self.write_to_address(address, &data)
                }
                Err(err) => {
                    // we still need to write to the target location before reporting the error
                    self.write_to_address(address, &Data::new_top(*size))?;
                    Err(err)
                }
            }
        } else {
            panic!("Expected store expression")
        }
    }

    /// If the pointer contains a reference to the stack with offset >= 0, replace it with a pointer
    /// pointing to all possible caller IDs.
    fn adjust_pointer_for_read(&self, address: &Data) -> Data {
        if let Data::Pointer(pointer) = address {
            let mut new_targets = BTreeMap::new();
            for (id, offset) in pointer.targets() {
                if *id == self.stack_id {
                    match offset {
                        BitvectorDomain::Value(offset_val) => {
                            if offset_val.try_to_i64().unwrap() >= 0
                                && !self.caller_stack_ids.is_empty()
                            {
                                for caller_id in self.caller_stack_ids.iter() {
                                    new_targets.insert(caller_id.clone(), offset.clone());
                                }
                            // Note that the id of the current stack frame was *not* added.
                            } else {
                                new_targets.insert(id.clone(), offset.clone());
                            }
                        }
                        BitvectorDomain::Top(_bitsize) => {
                            for caller_id in self.caller_stack_ids.iter() {
                                new_targets.insert(caller_id.clone(), offset.clone());
                            }
                            // Note that we also add the id of the current stack frame
                            new_targets.insert(id.clone(), offset.clone());
                        }
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
    pub fn eval(&self, expression: &Expression) -> Result<Data, Error> {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(&variable),
            Const(bitvector) => Ok(bitvector.clone().into()),
            // TODO: implement handling of endianness for loads and writes!
            Load {
                memory: _,
                address,
                endian: _,
                size,
            } => Ok(self
                .memory
                .get_value(&self.adjust_pointer_for_read(&self.eval(address)?), *size)?),
            Store { .. } => {
                // This does not return an error, but panics outright.
                // If this would return an error, it would hide a side effect, which is not allowed to happen.
                panic!("Store expression cannot be evaluated!")
            }
            BinOp { op, lhs, rhs } => {
                if *op == crate::bil::BinOpType::XOR && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Ok(Bitvector::zero(apint::BitWidth::new(
                        self.eval(lhs)?.bitsize() as usize
                    )?)
                    .into());
                }
                let (left, right) = (self.eval(lhs)?, self.eval(rhs)?);
                Ok(left.bin_op(*op, &right))
            }
            UnOp { op, arg } => Ok(self.eval(arg)?.un_op(*op)),
            Cast { kind, width, arg } => Ok(self.eval(arg)?.cast(*kind, *width)),
            Let {
                var: _,
                bound_exp: _,
                body_exp: _,
            } => Err(anyhow!("Let binding expression handling not implemented")),
            Unknown { description, type_ } => {
                if let crate::bil::variable::Type::Immediate(bitsize) = type_ {
                    Ok(Data::new_top(*bitsize))
                } else {
                    Err(anyhow!("Unknown Memory operation: {}", description))
                }
            }
            IfThenElse {
                condition,
                true_exp,
                false_exp,
            } => match self.eval(condition)? {
                x if x == Bitvector::from_bit(false).into() => self.eval(false_exp),
                x if x == Bitvector::from_bit(true).into() => self.eval(true_exp),
                _ => Ok(self.eval(true_exp)?.merge(&self.eval(false_exp)?)),
            },
            Extract {
                low_bit,
                high_bit,
                arg,
            } => Ok(self.eval(arg)?.extract(*low_bit, *high_bit)),
            Concat { left, right } => Ok(self.eval(left)?.concat(&self.eval(right)?)),
        }
    }

    /// Check if an expression contains a use-after-free
    pub fn contains_access_of_dangling_memory(&self, expression: &Expression) -> bool {
        use Expression::*;
        match expression {
            Var(_) | Const(_) | Unknown { .. } => false,
            Load {
                address: address_exp,
                ..
            } => {
                if let Ok(pointer) = self.eval(address_exp) {
                    self.memory.is_dangling_pointer(&pointer, true)
                        || self.contains_access_of_dangling_memory(address_exp)
                } else {
                    false
                }
            }
            Store {
                memory: _,
                address: address_exp,
                value: value_exp,
                ..
            } => {
                let address_check = if let Ok(pointer) = self.eval(address_exp) {
                    self.memory.is_dangling_pointer(&pointer, true)
                } else {
                    false
                };
                address_check
                    || self.contains_access_of_dangling_memory(address_exp)
                    || self.contains_access_of_dangling_memory(value_exp)
            }
            BinOp { op: _, lhs, rhs } => {
                self.contains_access_of_dangling_memory(lhs)
                    || self.contains_access_of_dangling_memory(rhs)
            }
            UnOp { op: _, arg } => self.contains_access_of_dangling_memory(arg),
            Cast {
                kind: _,
                width: _,
                arg,
            } => self.contains_access_of_dangling_memory(arg),
            Let {
                var: _,
                bound_exp,
                body_exp,
            } => {
                self.contains_access_of_dangling_memory(bound_exp)
                    || self.contains_access_of_dangling_memory(body_exp)
            }
            IfThenElse {
                condition,
                true_exp,
                false_exp,
            } => {
                self.contains_access_of_dangling_memory(condition)
                    || self.contains_access_of_dangling_memory(true_exp)
                    || self.contains_access_of_dangling_memory(false_exp)
            }
            Extract {
                low_bit: _,
                high_bit: _,
                arg,
            } => self.contains_access_of_dangling_memory(arg),
            Concat { left, right } => {
                self.contains_access_of_dangling_memory(left)
                    || self.contains_access_of_dangling_memory(right)
            }
        }
    }

    /// If  the given address is a positive stack offset and `self.caller_stack_ids` is non-empty,
    /// i.e. it is an access to the caller stack, return the offset.
    ///
    /// In all other cases, including the case that the address has more than one target, return `None`.
    fn unwrap_offset_if_caller_stack_address(&self, address: &Data) -> Option<BitvectorDomain> {
        if self.caller_stack_ids.is_empty() {
            return None;
        }
        if let Data::Pointer(pointer) = address {
            match (pointer.targets().len(), pointer.targets().iter().next()) {
                (1, Some((id, offset))) if self.stack_id == *id => {
                    if let BitvectorDomain::Value(offset_val) = offset {
                        if offset_val.try_to_i64().unwrap() >= 0 {
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