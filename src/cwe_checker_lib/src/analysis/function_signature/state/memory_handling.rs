use super::State;
use super::POINTER_RECURSION_DEPTH_LIMIT;
use crate::abstract_domain::*;
use crate::intermediate_representation::*;

impl State {
    /// Load the value at the given address.
    ///
    /// Only values on the stack and in registers are tracked directly.
    /// For all other values abstract location strings are generated
    /// that track how the pointer to the value is computed.
    ///
    /// This function does not set any access flags for input IDs in the address value.
    pub fn load_value(
        &mut self,
        address: DataDomain<BitvectorDomain>,
        size: ByteSize,
        global_memory: Option<&RuntimeMemoryImage>,
    ) -> DataDomain<BitvectorDomain> {
        let mut loaded_value = DataDomain::new_empty(size);
        for (id, offset) in address.get_relative_values() {
            loaded_value = loaded_value.merge(&self.load_value_via_id_and_offset(id, offset, size));
        }
        if let Some(global_address) = address.get_absolute_value() {
            loaded_value =
                loaded_value.merge(&self.load_global_address(global_address, size, global_memory));
        }
        if address.contains_top() {
            loaded_value.set_contains_top_flag();
        }
        loaded_value
    }

    /// Load the value whose position is given by derefencing the given ID and then adding an offset.
    ///
    /// If the ID is the stack then this function actually loads the value at the given stack position.
    /// Otherwise it only generates the abstract location of the value and returns it as a relative value.
    fn load_value_via_id_and_offset(
        &mut self,
        id: &AbstractIdentifier,
        offset: &BitvectorDomain,
        size: ByteSize,
    ) -> DataDomain<BitvectorDomain> {
        if *id == self.stack_id {
            // Try to load a value from the stack (which may generate a new stack parameter)
            match offset.try_to_bitvec() {
                Ok(stack_offset) => self.load_value_from_stack(stack_offset, size),
                Err(_) => DataDomain::new_top(size),
            }
        } else if let (true, Ok(constant_offset)) = (
            id.get_location().recursion_depth() < POINTER_RECURSION_DEPTH_LIMIT,
            offset.try_to_offset(),
        ) {
            // Extend the abstract location string
            let new_id = AbstractIdentifier::new(
                id.get_tid().clone(),
                id.get_location()
                    .clone()
                    .dereferenced(size, self.stack_id.bytesize())
                    .with_offset_addendum(constant_offset),
            );
            DataDomain::from_target(new_id, Bitvector::zero(size.into()).into())
        } else {
            // The abstract location string cannot be extended
            DataDomain::new_top(size)
        }
    }

    /// Load a value from the global address space.
    /// If the address is located in writeable global memory then generate a new abstract ID for the value
    /// and return a value relative to the new ID.
    fn load_global_address(
        &mut self,
        global_address: &BitvectorDomain,
        size: ByteSize,
        global_memory: Option<&RuntimeMemoryImage>,
    ) -> DataDomain<BitvectorDomain> {
        if let (Ok(offset), Some(global_mem)) = (global_address.try_to_bitvec(), global_memory) {
            match global_mem.read(&offset, size) {
                Ok(Some(value)) => value.into(),
                Ok(None) => {
                    let address = global_address.try_to_offset().unwrap() as u64;
                    let global_mem_location = AbstractLocation::GlobalAddress { address, size };
                    let global_mem_id = AbstractIdentifier::new(
                        self.get_current_function_tid().clone(),
                        global_mem_location,
                    );
                    DataDomain::from_target(global_mem_id, Bitvector::zero(size.into()).into())
                }
                Err(_) => DataDomain::new_top(size),
            }
        } else {
            DataDomain::new_top(size)
        }
    }

    /// Load the value at the given stack offset.
    /// If the offset is non-negative a corresponding stack parameter is generated if necessary.
    pub fn load_value_from_stack(
        &mut self,
        stack_offset: Bitvector,
        size: ByteSize,
    ) -> DataDomain<BitvectorDomain> {
        if !stack_offset.sign_bit().to_bool() {
            // Stack offset is nonnegative, i.e. this is a stack parameter access.
            self.get_stack_param(stack_offset, size)
        } else {
            self.stack.get(stack_offset, size)
        }
    }

    /// Load a value of unknown bytesize at the given stack offset.
    /// If the offset is non-negative, a corresponding stack parameter is generated if necessary.
    ///
    /// One must be careful to not rely on the correctness of the bytesize of the returned value!
    /// If the size of the value cannot be guessed from the contents of the stack,
    /// then a size of 1 byte is assumed, which will be wrong in general!
    pub fn load_unsized_value_from_stack(
        &mut self,
        offset: Bitvector,
    ) -> DataDomain<BitvectorDomain> {
        if !offset.sign_bit().to_bool() {
            // This is a pointer to a stack parameter of the current function
            self.stack
                .get_unsized(offset.clone())
                .unwrap_or_else(|| self.get_stack_param(offset, ByteSize::new(1)))
        } else {
            self.stack
                .get_unsized(offset)
                .unwrap_or_else(|| DataDomain::new_top(ByteSize::new(1)))
        }
    }

    /// If `address` is a stack offset, then write `value` onto the stack.
    ///
    /// If address points to a stack parameter, whose ID does not yet exists,
    /// then the ID is generated and added to the tracked IDs.
    ///
    /// This function does not set any access flags for input IDs of the given address or value.
    pub fn write_value(
        &mut self,
        address: DataDomain<BitvectorDomain>,
        value: DataDomain<BitvectorDomain>,
    ) {
        if let Some(stack_offset) = self.get_offset_if_exact_stack_pointer(&address) {
            if !stack_offset.sign_bit().to_bool() {
                // We generate a new stack parameter object, but do not set any access flags,
                // since the stack parameter is not accessed but overwritten.
                let _ = self
                    .generate_stack_param_id_if_nonexistent(stack_offset.clone(), value.bytesize());
            }
            self.stack.add(value, stack_offset);
        } else if let Some(stack_offset_domain) = address.get_relative_values().get(&self.stack_id)
        {
            if let Ok(stack_offset) = stack_offset_domain.try_to_bitvec() {
                if !stack_offset.sign_bit().to_bool() {
                    // We generate a new stack parameter object, but do not set any access flags,
                    // since the stack parameter is not accessed but overwritten.
                    let _ = self.generate_stack_param_id_if_nonexistent(
                        stack_offset.clone(),
                        value.bytesize(),
                    );
                }
                let previous_value = self.stack.get(stack_offset.clone(), value.bytesize());
                self.stack.add(previous_value.merge(&value), stack_offset);
            } else {
                self.stack.mark_all_values_as_top();
            }
        }
    }

    /// Get the value located at a positive stack offset.
    /// This function panics if the address is a negative offset.
    ///
    /// If no corresponding stack parameter ID exists for the value,
    /// generate it and then return it as an unmodified stack parameter.
    /// Otherwise just read the value at the given stack address.
    fn get_stack_param(
        &mut self,
        address: Bitvector,
        size: ByteSize,
    ) -> DataDomain<BitvectorDomain> {
        assert!(!address.sign_bit().to_bool());
        if let Some(param_id) = self.generate_stack_param_id_if_nonexistent(address.clone(), size) {
            let stack_param =
                DataDomain::from_target(param_id, Bitvector::zero(size.into()).into());
            self.stack.add(stack_param.clone(), address);
            stack_param
        } else {
            self.stack.get(address, size)
        }
    }

    /// If the address is an exactly known pointer to the stack with a constant offset, then return the offset.
    pub fn get_offset_if_exact_stack_pointer(
        &self,
        address: &DataDomain<BitvectorDomain>,
    ) -> Option<Bitvector> {
        if let Some((target, offset)) = address.get_if_unique_target() {
            if *target == self.stack_id {
                return offset.try_to_bitvec().ok();
            }
        }
        None
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{bitvec, variable};

    /// Mock an abstract ID representing the stack.
    fn mock_stack_id() -> AbstractIdentifier {
        AbstractIdentifier::from_var(Tid::new("mock_fn"), &variable!("sp:4"))
    }

    /// Mock an abstract ID of a stack parameter
    fn mock_stack_param_id(offset: i64, size: u64) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("mock_fn"),
            AbstractLocation::from_stack_position(
                mock_stack_id().unwrap_register(),
                offset,
                ByteSize::new(size),
            ),
        )
    }

    #[test]
    fn test_get_offset_if_exact_stack_pointer() {
        let state = State::mock_arm32();
        let stack_pointer =
            DataDomain::from_target(mock_stack_id(), Bitvector::from_i32(-10).into());
        assert_eq!(
            state.get_offset_if_exact_stack_pointer(&stack_pointer),
            Some(Bitvector::from_i32(-10))
        );
    }

    #[test]
    fn test_get_stack_param() {
        // Reading a previously non-existing stack parameter
        let mut state = State::mock_arm32();
        let stack_param = state.get_stack_param(bitvec!("0xc:4"), ByteSize::new(8));
        let expected_stack_id = AbstractIdentifier::mock_nested("mock_fn", "sp:4", &[12], 8);
        let expected_value =
            DataDomain::from_target(expected_stack_id.clone(), bitvec!("0x0:8").into());
        assert_eq!(&stack_param, &expected_value);
        assert!(state.tracked_ids.contains_key(&expected_stack_id));
        // Reading the stack parameter again. The position should still contain the stack parameter.
        let stack_param = state.get_stack_param(bitvec!("0xc:4"), ByteSize::new(8));
        assert_eq!(&stack_param, &expected_value);
        // Reading the stack parameter after it has been overwritten with a value.
        state
            .stack
            .insert_at_byte_index(bitvec!("0x2a:8").into(), 12);
        let value = state.get_stack_param(bitvec!("0xc:4"), ByteSize::new(8));
        assert_eq!(value, bitvec!("0x2a:8").into());
    }

    #[test]
    fn test_store_and_load_from_stack() {
        let mut state = State::mock_arm32();
        let address = DataDomain::from_target(mock_stack_id(), bitvec!("-4:4").into());
        let value: DataDomain<BitvectorDomain> = bitvec!("0x0:4").into();
        // write and load a value to the current stack frame
        state.write_value(address.clone(), value.clone());
        assert_eq!(state.stack.iter().len(), 1);
        assert_eq!(
            state.stack.get(bitvec!("-4:4"), ByteSize::new(4)),
            value.clone()
        );
        assert_eq!(state.load_value(address, ByteSize::new(4), None), value);
        // Load a parameter register and check that the parameter gets generated
        let address = DataDomain::from_target(mock_stack_id(), bitvec!("0x4:4").into());
        let stack_param_id = mock_stack_param_id(4, 4);
        let stack_param = DataDomain::from_target(stack_param_id.clone(), bitvec!("0x0:4").into());
        assert_eq!(state.tracked_ids.iter().len(), 6);
        assert_eq!(
            state.load_value(address.clone(), ByteSize::new(4), None),
            stack_param
        );
        assert_eq!(state.tracked_ids.iter().len(), 7);
        assert_eq!(
            state
                .tracked_ids
                .get(&stack_param_id)
                .unwrap()
                .is_accessed(),
            false
        ); // The load method does not set access flags.
    }

    #[test]
    fn test_load_unsized_from_stack() {
        let mut state = State::mock_arm32();
        // Load an existing stack param (generated by a sized load at the same address)
        let address = DataDomain::from_target(mock_stack_id(), bitvec!("0x0:4").into());
        let stack_param_id = mock_stack_param_id(0, 4);
        let stack_param = DataDomain::from_target(stack_param_id.clone(), bitvec!("0x0:4").into());
        state.load_value(address, ByteSize::new(4), None);
        let unsized_load = state.load_unsized_value_from_stack(bitvec!("0x0:4").into());
        assert_eq!(unsized_load, stack_param);
        assert!(state.tracked_ids.get(&stack_param_id).is_some());
        // Load a non-existing stack param
        let stack_param_id = mock_stack_param_id(4, 1);
        let stack_param = DataDomain::from_target(stack_param_id.clone(), bitvec!("0x0:1").into());
        let unsized_load = state.load_unsized_value_from_stack(bitvec!("0x4:4"));
        assert_eq!(unsized_load, stack_param);
        assert!(state.tracked_ids.get(&stack_param_id).is_some());
        // Unsized load from the current stack frame
        let unsized_load = state.load_unsized_value_from_stack(bitvec!("-4:4"));
        assert_eq!(unsized_load, DataDomain::new_top(ByteSize::new(1)));
    }

    #[test]
    fn test_load_nested_pointers() {
        let mut state = State::mock_arm32();
        let global_memory = RuntimeMemoryImage::mock();
        let parent_id = AbstractIdentifier::mock_nested("mock_fn", "r0:4", &[4], 4);
        let pointer = DataDomain::from_target(parent_id.clone(), bitvec!("0x8:4").into());
        let loaded_value = state.load_value(pointer, ByteSize::new(4), Some(&global_memory));
        let expected_id = AbstractIdentifier::mock_nested("mock_fn", "r0:4", &[4, 8], 4);
        let expected_value = DataDomain::from_target(expected_id.clone(), bitvec!("0x0:4").into());
        assert_eq!(loaded_value, expected_value);
    }
}
