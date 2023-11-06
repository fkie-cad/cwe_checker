use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::abstract_domain::*;
use crate::intermediate_representation::*;
use crate::prelude::*;

use super::AccessPattern;

/// Methods of [`State`] related to handling call instructions.
mod call_handling;

/// The state tracks knowledge about known register values,
/// known values on the stack, and access patterns of tracked variables.
///
/// The values and access patterns are tracked as upper bounds.
/// For example, if some access flag for a variable is set, then the variable may have been accessed,
/// but it does not have to be accessed in the current state.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Known register values.
    register: DomainMap<Variable, DataDomain<BitvectorDomain>, MergeTopStrategy>,
    /// The abstract ID representing the stack of the current function.
    stack_id: AbstractIdentifier,
    /// The content of the current stack frame.
    stack: MemRegion<DataDomain<BitvectorDomain>>,
    /// Maps each tracked ID to an [`AccessPattern`], which tracks known access patterns to the object.
    tracked_ids: DomainMap<AbstractIdentifier, AccessPattern, UnionMergeStrategy>,
}

impl State {
    /// Generate a new state corresponding to the function start state for the given function TID.
    ///
    /// Only registers that are parameter registers in the given calling convention are added to the tracked IDs.
    pub fn new(
        func_tid: &Tid,
        stack_register: &Variable,
        calling_convention: &CallingConvention,
    ) -> State {
        let mut register_map = BTreeMap::new();
        let mut tracked_ids = BTreeMap::new();
        // Generate tracked IDs for all parameters and also add them to the register map
        for var in calling_convention.get_all_parameter_register() {
            let id = AbstractIdentifier::from_var(func_tid.clone(), var);
            let value =
                DataDomain::from_target(id.clone(), Bitvector::zero(var.size.into()).into());
            register_map.insert(var.clone(), value);
            if var != stack_register {
                tracked_ids.insert(id, AccessPattern::new());
            }
        }
        // Generate all stack-related objects
        let stack_id = AbstractIdentifier::from_var(func_tid.clone(), stack_register);
        let stack_value = DataDomain::from_target(
            stack_id.clone(),
            Bitvector::zero(stack_register.size.into()).into(),
        );
        register_map.insert(stack_register.clone(), stack_value);
        let stack = MemRegion::new(stack_register.size);

        State {
            register: DomainMap::from(register_map),
            stack_id,
            stack,
            tracked_ids: DomainMap::from(tracked_ids),
        }
    }

    /// Set the MIPS link register `t9` to the address of the function TID.
    ///
    /// According to the System V ABI for MIPS the caller has to save the callee address in register `t9`
    /// on a function call to position-independent code.
    /// This function manually sets `t9` to the correct value.
    ///
    /// Returns an error if the function address could not be parsed (e.g. for `UNKNOWN` addresses).
    pub fn set_mips_link_register(
        &mut self,
        fn_tid: &Tid,
        generic_pointer_size: ByteSize,
    ) -> Result<(), Error> {
        let link_register = Variable {
            name: "t9".into(),
            size: generic_pointer_size,
            is_temp: false,
        };
        let address = Bitvector::from_u64(u64::from_str_radix(&fn_tid.address, 16)?)
            .into_resize_unsigned(generic_pointer_size);
        // Note that we do not replace the absolute value by a relative value representing a global memory pointer.
        // Else we would risk every global variable to get assigned the same abstract ID.
        self.set_register(&link_register, address.into());
        Ok(())
    }

    /// Get the value of the given register in the current state.
    pub fn get_register(&self, register: &Variable) -> DataDomain<BitvectorDomain> {
        self.register
            .get(register)
            .cloned()
            .unwrap_or_else(|| DataDomain::new_top(register.size))
    }

    /// Set the value of the given register in the current state.
    pub fn set_register(&mut self, register: &Variable, value: DataDomain<BitvectorDomain>) {
        if value.is_top() {
            self.register.remove(register);
        } else {
            self.register.insert(register.clone(), value);
        }
    }

    /// Get the TID of the function that this state belongs to.
    pub fn get_current_function_tid(&self) -> &Tid {
        self.stack_id.get_tid()
    }

    /// Load the value at the given address.
    ///
    /// Only constant addresses on the stack are tracked.
    /// Thus this function will always return a `Top` domain for any address
    /// that may not be a stack address with constant offset.
    ///
    /// This function does not set any access flags for input IDs in the address value.
    pub fn load_value(
        &mut self,
        address: DataDomain<BitvectorDomain>,
        size: ByteSize,
        global_memory: Option<&RuntimeMemoryImage>,
    ) -> DataDomain<BitvectorDomain> {
        if let Some(stack_offset) = self.get_offset_if_exact_stack_pointer(&address) {
            self.load_value_from_stack(stack_offset, size)
        } else if let (Ok(global_address), Some(global_mem)) =
            (address.try_to_bitvec(), global_memory)
        {
            if let Ok(Some(value)) = global_mem.read(&global_address, size) {
                value.into()
            } else {
                DataDomain::new_top(size)
            }
        } else {
            DataDomain::new_top(size)
        }
    }

    /// Load the value at the given stack offset.
    /// If the offset is non-negative a corresponding stack parameter is generated if necessary.
    fn load_value_from_stack(
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
    fn load_unsized_value_from_stack(&mut self, offset: Bitvector) -> DataDomain<BitvectorDomain> {
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
            // We generate a new stack parameter object, but do not set any access flags,
            // since the stack parameter is not accessed but overwritten.
            if !stack_offset.sign_bit().to_bool() {
                let _ = self
                    .generate_stack_param_id_if_nonexistent(stack_offset.clone(), value.bytesize());
            }
            self.stack.add(value, stack_offset);
        }
    }

    /// If the stack parameter ID corresponding to the given stack offset does not exist
    /// then generate it, add it to the list of tracked IDs, and return it.
    fn generate_stack_param_id_if_nonexistent(
        &mut self,
        stack_offset: Bitvector,
        size: ByteSize,
    ) -> Option<AbstractIdentifier> {
        assert!(!stack_offset.sign_bit().to_bool());
        let stack_pos = AbstractLocation::from_stack_position(
            self.stack_id.unwrap_register(),
            stack_offset.try_to_i64().unwrap(),
            size,
        );
        let param_id = AbstractIdentifier::new(self.stack_id.get_tid().clone(), stack_pos);
        if self.tracked_ids.contains_key(&param_id) {
            None
        } else {
            self.tracked_ids
                .insert(param_id.clone(), AccessPattern::new());
            Some(param_id)
        }
    }

    /// Add an abstract ID to the set of tracked IDs if it is not already tracked.
    /// No access flags are set if the ID was not already tracked.
    pub fn add_id_to_tracked_ids(&mut self, id: &AbstractIdentifier) {
        if self.tracked_ids.get(id).is_none() {
            self.tracked_ids.insert(id.clone(), AccessPattern::new());
        }
    }

    /// Get the value located at a positive stack offset.
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

    /// Merges the access pattern of the given abstract identifer in `self` with the provided access pattern.
    ///
    /// Does not add the identifier to the list of tracked identifiers if it is not already tracked in `self`.
    pub fn merge_access_pattern_of_id(
        &mut self,
        id: &AbstractIdentifier,
        access_pattern: &AccessPattern,
    ) {
        if let Some(object) = self.tracked_ids.get_mut(id) {
            *object = object.merge(access_pattern);
        }
    }

    /// Evaluate the value of the given expression on the current state.
    pub fn eval(&self, expression: &Expression) -> DataDomain<BitvectorDomain> {
        match expression {
            Expression::Var(var) => self.get_register(var),
            Expression::Const(bitvector) => bitvector.clone().into(),
            Expression::BinOp { op, lhs, rhs } => self.eval(lhs).bin_op(*op, &self.eval(rhs)),
            Expression::UnOp { op, arg } => self.eval(arg).un_op(*op),
            Expression::Cast { op, size, arg } => self.eval(arg).cast(*op, *size),
            Expression::Unknown {
                description: _,
                size,
            } => DataDomain::new_top(*size),
            Expression::Subpiece {
                low_byte,
                size,
                arg,
            } => self.eval(arg).subpiece(*low_byte, *size),
        }
    }

    /// Evaluate the value of the given parameter on the current state.
    ///
    /// Note that this may alter the state
    /// since stack parameters of the argument may access stack parameters of the the current stack frame,
    /// which may need to be generated first.
    pub fn eval_parameter_arg(&mut self, parameter: &Arg) -> DataDomain<BitvectorDomain> {
        match parameter {
            Arg::Register { expr, data_type: _ } => self.eval(expr),
            Arg::Stack {
                address,
                size,
                data_type: _,
            } => {
                self.set_deref_flag_for_input_ids_of_expression(address);
                let address = self.eval(address);
                self.load_value(address, *size, None)
            }
        }
    }

    /// If the given expression is not an [`Expression::Var`] set the read flags
    /// for all IDs that may be referenced when computing the value of the expression.
    ///
    /// [`Expression::Var`] accesses also happen when writing a callee-saved register to the stack.
    /// This function can be used to prevent accidentially flagging callee-saved registers as input registers.
    pub fn set_read_flag_for_input_ids_of_nontrivial_expression(
        &mut self,
        expression: &Expression,
    ) {
        match expression {
            Expression::Var(_) => (),
            _ => self.set_read_flag_for_input_ids_of_expression(expression),
        }
    }

    /// Set the read flag for every ID that may be referenced when computing the value of the expression.
    pub fn set_read_flag_for_input_ids_of_expression(&mut self, expression: &Expression) {
        for register in expression.input_vars() {
            for id in self.get_register(register).referenced_ids() {
                if let Some(object) = self.tracked_ids.get_mut(id) {
                    object.set_read_flag();
                }
            }
        }
    }

    /// Set the read and dereferenced flag for every tracked ID
    /// that may be referenced when computing the value of the expression.
    pub fn set_deref_flag_for_input_ids_of_expression(&mut self, expression: &Expression) {
        for register in expression.input_vars() {
            self.set_deref_flag_for_contained_ids(&self.get_register(register));
        }
    }

    /// Set the read and mutably dereferenced flag for every tracked ID
    /// that may be referenced when computing the value of the expression.
    pub fn set_mutable_deref_flag_for_input_ids_of_expression(&mut self, expression: &Expression) {
        for register in expression.input_vars() {
            self.set_deref_mut_flag_for_contained_ids(&self.get_register(register));
        }
    }

    /// Set the read and dereferenced flag for every tracked ID contained in the given value.
    pub fn set_deref_flag_for_contained_ids(&mut self, value: &DataDomain<BitvectorDomain>) {
        for id in value.referenced_ids() {
            if let Some(object) = self.tracked_ids.get_mut(id) {
                object.set_read_flag();
                object.set_dereference_flag();
            }
        }
    }

    /// Set the read and mutably dereferenced flag for every tracked ID contained in the given value.
    pub fn set_deref_mut_flag_for_contained_ids(&mut self, value: &DataDomain<BitvectorDomain>) {
        for id in value.referenced_ids() {
            if let Some(object) = self.tracked_ids.get_mut(id) {
                object.set_read_flag();
                object.set_mutably_dereferenced_flag();
            }
        }
    }

    /// If the absolute value part of the given value might represent an address into writeable global memory
    /// then substitute it by a relative value relative to a new global memory ID.
    ///
    /// The generated ID will be also added to the tracked IDs of `self`.
    /// However, no access flags will be set for the newly generated ID.
    pub fn substitute_global_mem_address(
        &mut self,
        mut value: DataDomain<BitvectorDomain>,
        global_memory: &RuntimeMemoryImage,
    ) -> DataDomain<BitvectorDomain> {
        if value.bytesize() != self.stack_id.bytesize() {
            // Only pointer-sized values can represent global addresses.
            return value;
        } else if let Some(absolute_value) = value.get_absolute_value() {
            if let Ok(bitvec) = absolute_value.try_to_bitvec() {
                if let Ok(true) = global_memory.is_address_writeable(&bitvec) {
                    // The absolute value might be a pointer to global memory.
                    let global_id = AbstractIdentifier::from_global_address(
                        self.get_current_function_tid(),
                        &bitvec,
                    );
                    // Add the ID to the set of tracked IDs for the state.
                    self.add_id_to_tracked_ids(&global_id);
                    // Convert the absolute value to a relative value (relative the new global ID).
                    value = value.merge(&DataDomain::from_target(
                        global_id,
                        Bitvector::zero(value.bytesize().into()).into(),
                    ));
                    value.set_absolute_value(None);
                }
            }
        }
        value
    }
}

impl AbstractDomain for State {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        let stack_id = self.stack_id.clone();
        let stack = self.stack.merge(&other.stack);
        State {
            register: self.register.merge(&other.register),
            stack_id,
            stack,
            tracked_ids: self.tracked_ids.merge(&other.tracked_ids),
        }
    }

    /// The state does not have an explicit `Top` element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Generate a compact JSON-representation of the state for pretty printing.
    #[allow(dead_code)]
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut json_map = serde_json::Map::new();
        json_map.insert(
            "Stack-ID".to_string(),
            serde_json::Value::String(format!("{}", self.stack_id)),
        );
        let regs = self
            .register
            .iter()
            .map(|(var, value)| (format!("{var}"), value.to_json_compact()))
            .collect();
        json_map.insert("Register".to_string(), serde_json::Value::Object(regs));
        let access_patterns = self
            .tracked_ids
            .iter()
            .map(|(id, pattern)| {
                (
                    format!("{id}"),
                    serde_json::Value::String(format!("{pattern}")),
                )
            })
            .collect();
        json_map.insert(
            "Tracked IDs".to_string(),
            serde_json::Value::Object(access_patterns),
        );
        let stack = self
            .stack
            .iter()
            .map(|(index, value)| (format!("{}", *index), value.to_json_compact()))
            .collect();
        json_map.insert("Stack".to_string(), serde_json::Value::Object(stack));
        serde_json::Value::Object(json_map)
    }
}

#[cfg(test)]
mod tests;
