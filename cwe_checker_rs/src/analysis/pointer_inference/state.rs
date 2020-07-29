use super::data::*;
use super::identifier::{AbstractIdentifier, AbstractLocation};
use super::object_list::AbstractObjectList;
use crate::analysis::abstract_domain::*;
use crate::bil::*;
use crate::prelude::*;
use crate::term::symbol::ExternSymbol;
use std::collections::{BTreeMap, BTreeSet};

/// This struct contains all information known about the state at a specific point of time.
///
/// Notes:
/// - The *stack_id* is the identifier of the current stack frame.
/// Only reads and writes with offset less than 0 are permitted for it
/// - The *caller_stack_ids* contain all known identifier of caller stack frames.
/// If a read to an offset >= 0 corresponding to the current stack frame happens, it is considered
/// a merge read to all caller stack frames.
/// A write to an offset >= 0 corresponding to the current stack frame writes to all caller stack frames.
/// - The caller_stack_ids are given by the stack pointer at time of the call.
/// This way we can distinguish caller stack frames even if one function calls another several times.
/// - The ids_known_to_caller contains all ids directly known to some caller.
/// Objects referenced by these ids cannot be removed from the state, as some caller may have a reference to them.
/// This is not recursive, i.e. ids only known to the caller of the caller are not included.
/// If a caller does not pass a reference to a memory object to the callee (directly or indirectly),
/// it will not be included in ids_known_to_caller.
/// This way the caller can check on return, which memory objects could not have been accessed by the callee.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    register: BTreeMap<Variable, Data>,
    pub memory: AbstractObjectList,
    pub stack_id: AbstractIdentifier,
    pub caller_stack_ids: BTreeSet<AbstractIdentifier>,
    pub ids_known_to_caller: BTreeSet<AbstractIdentifier>,
}

impl State {
    /// Create a new state that contains only one memory object corresponding to the stack.
    /// The stack offset will be set to zero.
    pub fn new(stack_register: &Variable, function_tid: Tid) -> State {
        let stack_id = AbstractIdentifier::new(
            function_tid,
            AbstractLocation::from_var(stack_register).unwrap(),
        );
        let mut register: BTreeMap<Variable, Data> = BTreeMap::new();
        register.insert(
            stack_register.clone(),
            PointerDomain::new(
                stack_id.clone(),
                Bitvector::zero((stack_register.bitsize().unwrap() as usize).into()).into(),
            )
            .into(),
        );
        State {
            register,
            memory: AbstractObjectList::from_stack_id(
                stack_id.clone(),
                stack_register.bitsize().unwrap(),
            ),
            stack_id,
            caller_stack_ids: BTreeSet::new(),
            ids_known_to_caller: BTreeSet::new(),
        }
    }

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
            return Err(anyhow!("Variable is not a register type"));
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

    /// Clear all non-callee-saved registers from the state.
    /// This automatically also removes all virtual registers.
    /// The parameter is a list of callee-saved register names.
    pub fn clear_non_callee_saved_register(&mut self, callee_saved_register_names: &[String]) {
        let register = self
            .register
            .iter()
            .filter_map(|(register, value)| {
                if callee_saved_register_names
                    .iter()
                    .find(|reg_name| **reg_name == register.name)
                    .is_some()
                {
                    Some((register.clone(), value.clone()))
                } else {
                    None
                }
            })
            .collect();
        self.register = register;
    }

    /// evaluate the value of an expression in the current state
    pub fn eval(&self, expression: &Expression) -> Result<Data, Error> {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(&variable),
            Const(bitvector) => Ok(Data::bitvector(bitvector.clone())),
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
                    // TODO: implement bitsize() for expressions to remove the state.eval(lhs) hack
                    return Ok(Data::Value(BitvectorDomain::Value(Bitvector::zero(
                        apint::BitWidth::new(self.eval(lhs)?.bitsize() as usize)?,
                    ))));
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
                condition: _,
                true_exp,
                false_exp,
            } => Ok(self.eval(true_exp)?.merge(&self.eval(false_exp)?)),
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
                    self.memory.is_dangling_pointer(&pointer)
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
                    self.memory.is_dangling_pointer(&pointer)
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

    pub fn store_value(&mut self, address: &Data, value: &Data) -> Result<(), Error> {
        if let Data::Pointer(pointer) = self.adjust_pointer_for_read(address) {
            // TODO: This is a very inexact shortcut, as this write will unnecessarily merge caller memory regions.
            // A more precise solution would write to every caller memory region separately,
            // but would also need to check first whether the target memory region is unique or not.
            self.memory.set_value(pointer, value.clone())?;
            return Ok(());
        } else {
            // TODO: Implement recognition of stores to global memory.
            // Needs implementation of reads from global data first.
            return Err(anyhow!("Memory write to non-pointer data"));
        }
    }

    /// Write a value to the address one gets when evaluating the address expression.
    pub fn write_to_address(&mut self, address: &Expression, value: &Data) -> Result<(), Error> {
        // TODO: Depending on the separation logic, some memory may need to be invalidated in the error case.
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
            let data = self.eval(value).unwrap_or(Data::new_top(*size));
            assert_eq!(data.bitsize(), *size);
            // TODO: At the moment, both memory and endianness are ignored. Change that!
            return self.write_to_address(address, &data);
        } else {
            panic!("Expected store expression")
        }
    }

    /// Mark those parameter values of an extern function call, that are passed on the stack,
    /// as unknown data (since the function may modify them).
    pub fn clear_stack_parameter(&mut self, extern_call: &ExternSymbol) -> Result<(), Error> {
        // TODO: This needs a unit test to check whether stack parameters are cleared as expected!
        let mut result_log = Ok(());
        for arg in &extern_call.arguments {
            match &arg.location {
                Expression::Var(_) => {}
                location_expression => {
                    let arg_size = arg
                        .var
                        .bitsize()
                        .expect("Encountered argument with unknown size");
                    let data_top = Data::new_top(arg_size);
                    if let Err(err) = self.write_to_address(location_expression, &data_top) {
                        result_log = Err(err);
                    }
                }
            }
        }
        // We only return the last error encountered.
        return result_log;
    }

    /// merge two states
    pub fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.stack_id, other.stack_id);
        let mut merged_register = BTreeMap::new();
        for (register, other_value) in other.register.iter() {
            if let Some(value) = self.register.get(register) {
                let merged_value = value.merge(other_value);
                if merged_value.is_top() == false {
                    // We only have to keep non-top elements.
                    merged_register.insert(register.clone(), merged_value);
                }
            }
        }
        let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: merged_register,
            memory: merged_memory_objects,
            stack_id: self.stack_id.clone(),
            caller_stack_ids: self
                .caller_stack_ids
                .union(&other.caller_stack_ids)
                .cloned()
                .collect(),
            ids_known_to_caller: self
                .ids_known_to_caller
                .union(&other.ids_known_to_caller)
                .cloned()
                .collect(),
        }
    }

    /// If the pointer contains a reference to the stack with offset >= 0, replace it with a pointer
    /// pointing to all possible caller ids.
    fn adjust_pointer_for_read(&self, address: &Data) -> Data {
        // TODO: There is a rare special case that is not handled correctly
        // and might need a change in the way caller_ids get tracked to fix:
        // If no caller_id is present, one can read (and write) to addresses on the stack with positive offset
        // But if such a state gets merged with a state with caller_ids,
        // then these values at positive offsets get overshadowed by the new callers,
        // but they get not properly merged with the values from the other callers!
        if let Data::Pointer(pointer) = address {
            let mut new_targets = PointerDomain::with_targets(BTreeMap::new());
            for (id, offset) in pointer.iter_targets() {
                if *id == self.stack_id {
                    match offset {
                        BitvectorDomain::Value(offset_val) => {
                            if offset_val.try_to_i64().unwrap() >= 0
                                && self.caller_stack_ids.len() > 0
                            {
                                for caller_id in self.caller_stack_ids.iter() {
                                    new_targets.add_target(caller_id.clone(), offset.clone());
                                }
                            // Note that the id of the current stack frame was *not* added.
                            } else {
                                new_targets.add_target(id.clone(), offset.clone());
                            }
                        }
                        BitvectorDomain::Top(_bitsize) => {
                            for caller_id in self.caller_stack_ids.iter() {
                                new_targets.add_target(caller_id.clone(), offset.clone());
                            }
                            // Note that we also add the id of the current stack frame
                            new_targets.add_target(id.clone(), offset.clone());
                        }
                    }
                } else {
                    new_targets.add_target(id.clone(), offset.clone());
                }
            }
            return Data::Pointer(new_targets);
        } else {
            return address.clone();
        }
    }

    /// Replace all occurences of old_id with new_id and adjust offsets accordingly.
    /// This is needed to replace stack/caller ids on call and return instructions.
    ///
    /// **Example:**
    /// Assume the old_id points to offset 0 in the corresponding memory object and the new_id points to offset -32.
    /// Then the offset_adjustment is -32.
    /// The offset_adjustment gets *added* to the base offset in self.memory.ids (so that it points to offset -32 in the memory object),
    /// while it gets *subtracted* from all pointer values (so that they still point to the same spot in the corresponding memory object).
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        // TODO: This function does not adjust stack frame/caller stack frame relations!
        // Refactor so that the corresponding logic is contained in State.
        // Else this function can be used to generate invalid state on improper use!
        for register_data in self.register.values_mut() {
            register_data.replace_abstract_id(old_id, new_id, &(-offset_adjustment.clone()));
        }
        self.memory
            .replace_abstract_id(old_id, new_id, offset_adjustment);
        if &self.stack_id == old_id {
            self.stack_id = new_id.clone();
        }
        if self.caller_stack_ids.get(old_id).is_some() {
            self.caller_stack_ids.remove(old_id);
            self.caller_stack_ids.insert(new_id.clone());
        }
        if self.ids_known_to_caller.get(old_id).is_some() {
            self.ids_known_to_caller.remove(old_id);
            self.ids_known_to_caller.insert(new_id.clone());
        }
    }

    pub fn remove_unreferenced_objects(&mut self) {
        // get all referenced ids
        let mut referenced_ids = BTreeSet::new();
        for (_reg_name, data) in self.register.iter() {
            referenced_ids.append(&mut data.referenced_ids());
        }
        referenced_ids.insert(self.stack_id.clone());
        referenced_ids.append(&mut self.caller_stack_ids.clone());
        referenced_ids.append(&mut self.ids_known_to_caller.clone());
        referenced_ids = self.add_recursively_referenced_ids_to_id_set(referenced_ids);
        // remove unreferenced ids
        self.memory.remove_unused_ids(&referenced_ids);
    }

    pub fn add_recursively_referenced_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id);
                }
            }
        }
        return ids;
    }

    /// Merge the callee stack with the caller stack.
    ///
    /// This deletes the pointer from the callee_id to the corresponding memory object
    /// and updates all other references pointing to the callee_id to point to the caller_id.
    /// The offset adjustment is handled as in `replace_abstract_id`.
    ///
    /// Note that right now the content of the callee memory object is not merged into the caller memory object.
    /// In general this is the correct behaviour as the content below the stack pointer should be considered uninitialized memory after returning to the caller.
    /// TODO: Check whether compilers may deviate from this convention when optimizing aggressively.
    /// TODO: Also merge the memory objects!
    // TODO: write unit tests
    pub fn merge_callee_stack_to_caller_stack(
        &mut self,
        callee_id: &AbstractIdentifier,
        caller_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        self.memory.remove_object_pointer(callee_id);
        self.replace_abstract_id(callee_id, caller_id, offset_adjustment);
        // TODO: Add a check that makes sure no other ids point to the now obsolete callee stack object!
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    ///
    /// If this may cause double frees (i.e. the object in question may have been freed already),
    /// an error with the list of possibly already freed objects is returned.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &PointerDomain,
    ) -> Result<(), Vec<AbstractIdentifier>> {
        self.memory.mark_mem_object_as_freed(object_pointer)
    }

    /// Remove all virtual register from the state.
    /// This should only be done in cases where it is known that no virtual registers can be alive.
    /// Example: At the start of a basic block no virtual registers should be alive.
    pub fn remove_virtual_register(&mut self) {
        self.register = self
            .register
            .clone()
            .into_iter()
            .filter(|(register, _value)| register.is_temp == false)
            .collect();
    }

    /// Recursively remove all caller_stack_ids not corresponding to the given caller.
    pub fn remove_other_caller_stack_ids(&mut self, caller_id: &AbstractIdentifier) {
        let mut ids_to_remove = self.caller_stack_ids.clone();
        ids_to_remove.remove(caller_id);
        for register_value in self.register.values_mut() {
            register_value.remove_ids(&ids_to_remove);
        }
        self.memory.remove_ids(&ids_to_remove);
        self.caller_stack_ids = BTreeSet::new();
        self.caller_stack_ids.insert(caller_id.clone());
        self.ids_known_to_caller = self
            .ids_known_to_caller
            .difference(&ids_to_remove)
            .cloned()
            .collect();
    }

    /// Add those objects from the caller_state to self, that are not known to self.
    ///
    /// Since self does not know these objects, we assume that the current function could not have accessed
    /// them in any way during execution.
    /// This means they are unchanged from the moment of the call until the return from the call,
    /// thus we can simply copy their object-state from the moment of the call.
    pub fn readd_caller_objects(&mut self, caller_state: &State) {
        self.memory.append_unknown_objects(&caller_state.memory);
    }
}

impl State {
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut state_map = Map::new();
        let register = self
            .register
            .iter()
            .map(|(var, data)| (var.name.clone(), data.to_json_compact()))
            .collect();
        let register = Value::Object(register);
        state_map.insert("register".into(), register);
        state_map.insert("memory".into(), self.memory.to_json_compact());
        state_map.insert(
            "stack_id".into(),
            Value::String(format!("{}", self.stack_id)),
        );
        state_map.insert(
            "caller_stack_ids".into(),
            Value::Array(
                self.caller_stack_ids
                    .iter()
                    .map(|id| Value::String(format!("{}", id)))
                    .collect(),
            ),
        );
        state_map.insert(
            "ids_known_to_caller".into(),
            Value::Array(
                self.ids_known_to_caller
                    .iter()
                    .map(|id| Value::String(format!("{}", id)))
                    .collect(),
            ),
        );

        Value::Object(state_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: String) -> AbstractIdentifier {
        AbstractIdentifier::new(Tid::new("time0"), AbstractLocation::Register(name, 64))
    }

    fn register(name: &str) -> Variable {
        Variable {
            name: name.into(),
            type_: crate::bil::variable::Type::Immediate(64),
            is_temp: false,
        }
    }

    fn reg_add(name: &str, value: i64) -> Expression {
        Expression::BinOp {
            op: BinOpType::PLUS,
            lhs: Box::new(Expression::Var(register(name))),
            rhs: Box::new(Expression::Const(Bitvector::from_i64(value))),
        }
    }

    fn reg_sub(name: &str, value: i64) -> Expression {
        Expression::BinOp {
            op: BinOpType::MINUS,
            lhs: Box::new(Expression::Var(register(name))),
            rhs: Box::new(Expression::Const(Bitvector::from_i64(value))),
        }
    }

    fn store_exp(address: Expression, value: Expression) -> Expression {
        let mem_var = Variable {
            name: "mem".into(),
            type_: crate::bil::variable::Type::Memory {
                addr_size: 64,
                elem_size: 64,
            },
            is_temp: false,
        };
        Expression::Store {
            memory: Box::new(Expression::Var(mem_var)),
            address: Box::new(address),
            value: Box::new(value),
            endian: Endianness::LittleEndian,
            size: 64,
        }
    }

    fn load_exp(address: Expression) -> Expression {
        let mem_var = Variable {
            name: "mem".into(),
            type_: crate::bil::variable::Type::Memory {
                addr_size: 64,
                elem_size: 64,
            },
            is_temp: false,
        };
        Expression::Load {
            memory: Box::new(Expression::Var(mem_var)),
            address: Box::new(address),
            endian: Endianness::LittleEndian,
            size: 64,
        }
    }

    #[test]
    fn state() {
        use crate::analysis::pointer_inference::object::*;
        use crate::bil::Expression::*;
        let mut state = State::new(&register("RSP"), Tid::new("time0"));
        let stack_id = new_id("RSP".into());
        let stack_addr = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(8)));
        state
            .store_value(&stack_addr, &Data::Value(bv(42)))
            .unwrap();
        state.register.insert(register("RSP"), stack_addr.clone());
        let load_expr = Load {
            memory: Box::new(Var(register("RSP"))), // This is wrong, but the memory var is not checked at the moment (since we have only the one for RAM)
            address: Box::new(Var(register("RSP"))),
            endian: Endianness::LittleEndian,
            size: 64 as BitSize,
        };
        assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(42)));

        let mut other_state = State::new(&register("RSP"), Tid::new("time0"));
        state.register.insert(register("RAX"), Data::Value(bv(42)));
        other_state
            .register
            .insert(register("RSP"), stack_addr.clone());
        other_state
            .register
            .insert(register("RAX"), Data::Value(bv(42)));
        other_state
            .register
            .insert(register("RBX"), Data::Value(bv(35)));
        let merged_state = state.merge(&other_state);
        assert_eq!(merged_state.register[&register("RAX")], Data::Value(bv(42)));
        assert_eq!(merged_state.register.get(&register("RBX")), None);
        assert_eq!(merged_state.eval(&load_expr).unwrap(), Data::new_top(64));

        // Test pointer adjustment on reads
        state
            .memory
            .add_abstract_object(new_id("caller".into()), bv(0), ObjectType::Stack, 64);
        state.caller_stack_ids.insert(new_id("caller".into()));
        state
            .store_value(&stack_addr, &Data::Value(bv(15)))
            .unwrap();
        assert_eq!(
            state
                .memory
                .get_value(
                    &Data::Pointer(PointerDomain::new(new_id("caller".into()), bv(8))),
                    64
                )
                .unwrap(),
            Data::Value(bv(15))
        );
        assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(15)));

        // Test replace_abstract_id
        let pointer = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16)));
        state.register.insert(register("RSP"), pointer.clone());
        state.store_value(&pointer, &Data::Value(bv(7))).unwrap();
        assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(7)));
        state.replace_abstract_id(&stack_id, &new_id("callee".into()), &bv(-8));
        assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(7)));
        assert_eq!(
            state
                .memory
                .get_value(
                    &Data::Pointer(PointerDomain::new(new_id("callee".into()), bv(-8))),
                    64
                )
                .unwrap(),
            Data::Value(bv(7))
        );
        assert_eq!(
            state
                .memory
                .get_value(
                    &Data::Pointer(PointerDomain::new(new_id("callee".into()), bv(-16))),
                    64
                )
                .unwrap(),
            Data::new_top(64)
        );

        state
            .memory
            .add_abstract_object(new_id("heap_obj".into()), bv(0), ObjectType::Heap, 64);
        assert_eq!(state.memory.get_num_objects(), 3);
        state.remove_unreferenced_objects();
        assert_eq!(state.memory.get_num_objects(), 2);
    }

    #[test]
    fn handle_store() {
        use crate::bil::Expression::*;
        let mut state = State::new(&register("RSP"), Tid::new("time0"));
        let stack_id = new_id("RSP".into());
        assert_eq!(
            state.eval(&Var(register("RSP"))).unwrap(),
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0)))
        );

        state
            .handle_register_assign(&register("RSP"), &reg_sub("RSP", 32))
            .unwrap();
        assert_eq!(
            state.eval(&Var(register("RSP"))).unwrap(),
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-32)))
        );
        state
            .handle_register_assign(&register("RSP"), &reg_add("RSP", -8))
            .unwrap();
        assert_eq!(
            state.eval(&Var(register("RSP"))).unwrap(),
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-40)))
        );

        state
            .handle_store_exp(&store_exp(reg_add("RSP", 8), Const(Bitvector::from_i64(1))))
            .unwrap();
        state
            .handle_store_exp(&store_exp(reg_sub("RSP", 8), Const(Bitvector::from_i64(2))))
            .unwrap();
        state
            .handle_store_exp(&store_exp(
                reg_add("RSP", -16),
                Const(Bitvector::from_i64(3)),
            ))
            .unwrap();
        state
            .handle_register_assign(&register("RSP"), &reg_sub("RSP", 4))
            .unwrap();

        assert_eq!(
            state.eval(&load_exp(reg_add("RSP", 12))).unwrap(),
            bv(1).into()
        );
        assert_eq!(
            state.eval(&load_exp(reg_sub("RSP", 4))).unwrap(),
            bv(2).into()
        );
        assert_eq!(
            state.eval(&load_exp(reg_add("RSP", -12))).unwrap(),
            bv(3).into()
        );
    }
}
