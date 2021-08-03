use super::object_list::AbstractObjectList;
use super::{Data, ValueDomain};
use crate::abstract_domain::*;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::binary::RuntimeMemoryImage;
use std::collections::{BTreeMap, BTreeSet};

mod access_handling;

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    register: BTreeMap<Variable, Data>,
    /// The list of all known memory objects.
    pub memory: AbstractObjectList,
    /// The abstract identifier of the current stack frame.
    /// It points to the base of the stack frame, i.e. only negative offsets point into the current stack frame.
    pub stack_id: AbstractIdentifier,
    /// All known IDs of caller stack frames.
    /// Note that these IDs are named after the callsite,
    /// i.e. we can distinguish every callsite and for recursive functions the caller and current stack frames have different IDs.
    ///
    /// Writes to the current stack frame with offset >= 0 are written to *all* caller stack frames.
    /// Reads to the current stack frame with offset >= 0 are handled as merge-read from all caller stack frames.
    pub caller_stack_ids: BTreeSet<AbstractIdentifier>,
    /// All IDs of objects that are known to some caller.
    /// This is an overapproximation of all object IDs that may have been passed as parameters to the function.
    /// The corresponding objects are not allowed to be deleted (even if no pointer to them exists anymore)
    /// so that after returning from a call the caller can recover their modified contents
    /// and the callee does not accidentally delete this information if it loses all pointers to an object.
    ///
    /// Note that IDs that the callee should not have access to are not included here.
    /// For these IDs the caller can assume that the contents of the corresponding memory object were not accessed or modified by the call.
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
            Data::from_target(
                stack_id.clone(),
                Bitvector::zero(apint::BitWidth::from(stack_register.size)).into(),
            ),
        );
        State {
            register,
            memory: AbstractObjectList::from_stack_id(stack_id.clone(), stack_register.size),
            stack_id,
            caller_stack_ids: BTreeSet::new(),
            ids_known_to_caller: BTreeSet::new(),
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
                    .any(|reg_name| **reg_name == register.name)
                {
                    Some((register.clone(), value.clone()))
                } else {
                    None
                }
            })
            .collect();
        self.register = register;
    }

    /// Mark those parameter values of an extern function call, that are passed on the stack,
    /// as unknown data (since the function may modify them).
    pub fn clear_stack_parameter(
        &mut self,
        extern_call: &ExternSymbol,
        stack_pointer_register: &Variable,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        let mut result_log = Ok(());
        for arg in &extern_call.parameters {
            match arg {
                Arg::Register { .. } => (),
                Arg::Stack { offset, size, .. } => {
                    let data_top = Data::new_top(*size);
                    let location_expression =
                        Expression::Var(stack_pointer_register.clone()).plus_const(*offset);
                    if let Err(err) =
                        self.write_to_address(&location_expression, &data_top, global_memory)
                    {
                        result_log = Err(err);
                    }
                }
            }
        }
        // We only return the last error encountered.
        result_log
    }

    /// Replace all occurences of old_id with new_id and adjust offsets accordingly.
    /// This is needed to replace stack/caller IDs on call and return instructions.
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
        offset_adjustment: &ValueDomain,
    ) {
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

    /// Remove all objects that cannot longer be reached by any known pointer.
    /// This does not remove objects, where some caller may still know a pointer to the object.
    ///
    /// The function uses an underapproximation of all possible pointer targets contained in a memory object.
    /// This keeps the number of tracked objects reasonably small.
    pub fn remove_unreferenced_objects(&mut self) {
        // get all referenced IDs
        let mut referenced_ids = BTreeSet::new();
        for (_reg_name, data) in self.register.iter() {
            referenced_ids.extend(data.referenced_ids().cloned());
        }
        referenced_ids.insert(self.stack_id.clone());
        referenced_ids.append(&mut self.caller_stack_ids.clone());
        referenced_ids.append(&mut self.ids_known_to_caller.clone());
        referenced_ids = self.add_directly_reachable_ids_to_id_set(referenced_ids);
        // remove unreferenced objects
        self.memory.remove_unused_objects(&referenced_ids);
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs reachable through concrete pointers contained in them to the set of IDs.
    ///
    /// This uses an underapproximation of the referenced IDs of a memory object,
    /// i.e. IDs may be missing if the analysis lost track of the corresponding pointer.
    pub fn add_directly_reachable_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_underapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Search (recursively) through all memory objects referenced by the given IDs
    /// and add all IDs contained in them to the set of IDs.
    ///
    /// This uses an overapproximation of the referenced IDs of a memory object,
    /// i.e. for a memory object it may add IDs as possible references
    /// where the corresponding reference is not longer present in the memory object.
    pub fn add_recursively_referenced_ids_to_id_set(
        &self,
        mut ids: BTreeSet<AbstractIdentifier>,
    ) -> BTreeSet<AbstractIdentifier> {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids_overapproximation(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id.clone());
                }
            }
        }
        ids
    }

    /// Merge the callee stack with the caller stack.
    ///
    /// This deletes the memory object corresponding to the callee_id
    /// and updates all other references pointing to the callee_id to point to the caller_id.
    /// The offset adjustment is handled as in `replace_abstract_id`.
    ///
    /// Note that right now the content of the callee memory object is *not* merged into the caller memory object.
    /// In general this is the correct behaviour
    /// as the content below the stack pointer should be considered uninitialized memory after returning to the caller.
    /// However, an aggressively optimizing compiler or an unknown calling convention may deviate from this.
    pub fn merge_callee_stack_to_caller_stack(
        &mut self,
        callee_id: &AbstractIdentifier,
        caller_id: &AbstractIdentifier,
        offset_adjustment: &ValueDomain,
    ) {
        self.memory.remove_object(callee_id);
        self.replace_abstract_id(callee_id, caller_id, offset_adjustment);
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    ///
    /// If this may cause double frees (i.e. the object in question may have been freed already),
    /// an error with the list of possibly already freed objects is returned.
    pub fn mark_mem_object_as_freed(
        &mut self,
        object_pointer: &Data,
    ) -> Result<(), Vec<(AbstractIdentifier, Error)>> {
        self.memory.mark_mem_object_as_freed(object_pointer)
    }

    /// Remove all virtual register from the state.
    /// This should only be done in cases where it is known that no virtual registers can be alive.
    ///
    /// Example: At the start of a basic block no virtual registers should be alive.
    pub fn remove_virtual_register(&mut self) {
        self.register = self
            .register
            .clone()
            .into_iter()
            .filter(|(register, _value)| !register.is_temp)
            .collect();
    }

    /// Recursively remove all `caller_stack_ids` not corresponding to the given caller.
    pub fn remove_other_caller_stack_ids(&mut self, caller_id: &AbstractIdentifier) {
        let mut ids_to_remove = self.caller_stack_ids.clone();
        ids_to_remove.remove(caller_id);
        for register_value in self.register.values_mut() {
            register_value.remove_ids(&ids_to_remove);
            if register_value.is_empty() {
                *register_value = register_value.top();
            }
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

    /// Add those objects from the `caller_state` to `self`, that are not known to `self`.
    ///
    /// Since self does not know these objects, we assume that the current function could not have accessed
    /// them in any way during execution.
    /// This means they are unchanged from the moment of the call until the return from the call,
    /// thus we can simply copy their object-state from the moment of the call.
    pub fn readd_caller_objects(&mut self, caller_state: &State) {
        self.memory.append_unknown_objects(&caller_state.memory);
    }

    /// Restore the content of callee-saved registers from the caller state
    /// with the exception of the stack register.
    ///
    /// This function does not check what the callee state currently contains in these registers.
    /// If the callee does not adhere to the given calling convention, this may introduce analysis errors!
    /// It will also mask cases
    /// where a callee-saved register was incorrectly modified (e.g. because of a bug in the callee).
    pub fn restore_callee_saved_register(
        &mut self,
        caller_state: &State,
        cconv: &CallingConvention,
        stack_register: &Variable,
    ) {
        for (register, value) in caller_state.register.iter() {
            if register != stack_register
                && cconv
                    .callee_saved_register
                    .iter()
                    .any(|reg_name| *reg_name == register.name)
            {
                self.set_register(register, value.clone());
            }
        }
    }

    /// Remove all knowledge about the contents of callee-saved registers from the state.
    pub fn remove_callee_saved_register(&mut self, cconv: &CallingConvention) {
        let mut register_to_remove = Vec::new();
        for register in self.register.keys() {
            if cconv
                .callee_saved_register
                .iter()
                .any(|reg_name| *reg_name == register.name)
            {
                register_to_remove.push(register.clone());
            }
        }
        for register in register_to_remove {
            self.register.remove(&register);
        }
    }

    /// Try to restrict the input variables of `expression` on `self`
    /// so that `expression` only evaluates to values represented by the given `result`.
    ///
    /// If `expression` cannot evaluate to any value represented by `self`, return an error.
    ///
    /// This function may restrict to upper bounds of possible values
    /// if the restriction cannot be made exact,
    /// i.e. after calling this function the state may still contain values
    /// for which `expression` does not evaluate to values represented by `result`.
    pub fn specialize_by_expression_result(
        &mut self,
        expression: &Expression,
        result: Data,
    ) -> Result<(), Error> {
        if let Expression::Var(var) = expression {
            self.set_register(var, self.eval(expression).intersect(&result)?);
            Ok(())
        } else if let Expression::BinOp { op, lhs, rhs } = expression {
            self.specialize_by_binop_expression_result(op, lhs, rhs, result)
        } else {
            match expression {
                Expression::Var(_) => panic!(),
                Expression::Const(input_bitvec) => {
                    if let Ok(result_bitvec) = result.try_to_bitvec() {
                        if *input_bitvec == result_bitvec {
                            Ok(())
                        } else {
                            Err(anyhow!("Unsatisfiable state"))
                        }
                    } else {
                        Ok(())
                    }
                }
                Expression::BinOp { .. } => {
                    panic!() // Already handled above
                }
                Expression::UnOp { op, arg } => {
                    use UnOpType::*;
                    match op {
                        IntNegate | BoolNegate | Int2Comp => {
                            let intermediate_result = result.un_op(*op);
                            self.specialize_by_expression_result(arg, intermediate_result)
                        }
                        _ => Ok(()),
                    }
                }
                Expression::Cast { op, size: _, arg } => match op {
                    CastOpType::IntZExt | CastOpType::IntSExt => {
                        let intermediate_result = result.subpiece(ByteSize::new(0), arg.bytesize());
                        self.specialize_by_expression_result(arg, intermediate_result)
                    }
                    _ => Ok(()),
                },
                Expression::Unknown {
                    description: _,
                    size: _,
                } => Ok(()),
                Expression::Subpiece {
                    low_byte,
                    size,
                    arg,
                } => {
                    if *low_byte == ByteSize::new(0) {
                        if let Some(arg_value) = self.eval(expression).get_if_absolute_value() {
                            if arg_value.fits_into_size(*size) {
                                let intermediate_result =
                                    result.cast(CastOpType::IntSExt, arg.bytesize());
                                return self
                                    .specialize_by_expression_result(arg, intermediate_result);
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
    }

    /// Try to restrict the input variables of the given binary operation
    /// so that it only evaluates to the given `result_bitvec`.
    fn specialize_by_binop_expression_result(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
        result: Data,
    ) -> Result<(), Error> {
        match op {
            BinOpType::IntAdd => {
                let intermediate_result = result.clone() - self.eval(lhs);
                self.specialize_by_expression_result(rhs, intermediate_result)?;

                let intermediate_result = result - self.eval(rhs);
                self.specialize_by_expression_result(lhs, intermediate_result)?;

                return Ok(());
            }
            BinOpType::IntSub => {
                let intermediate_result: Data = self.eval(lhs) - result.clone();
                self.specialize_by_expression_result(rhs, intermediate_result)?;

                let intermediate_result = result + self.eval(rhs);
                self.specialize_by_expression_result(lhs, intermediate_result)?;

                return Ok(());
            }
            _ => (),
        }
        if let Ok(result_bitvec) = result.try_to_bitvec() {
            match op {
                BinOpType::IntXOr | BinOpType::BoolXOr => {
                    if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                        self.specialize_by_expression_result(
                            rhs,
                            (result_bitvec.clone() ^ &bitvec).into(),
                        )?;
                    }
                    if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                        self.specialize_by_expression_result(
                            lhs,
                            (result_bitvec ^ &bitvec).into(),
                        )?;
                    }
                    Ok(())
                }
                BinOpType::IntOr | BinOpType::BoolOr => {
                    if result_bitvec.is_zero() {
                        self.specialize_by_expression_result(lhs, result_bitvec.clone().into())?;
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(lhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(rhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(lhs, result_bitvec.into())
                    } else {
                        Ok(())
                    }
                }
                BinOpType::BoolAnd => {
                    if !result_bitvec.is_zero() {
                        self.specialize_by_expression_result(lhs, result_bitvec.clone().into())?;
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(lhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| !bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(rhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| !bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(lhs, result_bitvec.into())
                    } else {
                        Ok(())
                    }
                }
                BinOpType::IntEqual | BinOpType::IntNotEqual => {
                    match (op, !result_bitvec.is_zero()) {
                        (BinOpType::IntEqual, true) | (BinOpType::IntNotEqual, false) => {
                            // lhs == rhs
                            if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                                self.specialize_by_expression_result(rhs, bitvec.into())?;
                            }
                            if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                                self.specialize_by_expression_result(lhs, bitvec.into())?;
                            }
                            // Also specialize cases of pointer comparisons
                            self.specialize_pointer_comparison(&BinOpType::IntEqual, lhs, rhs)?;
                            Ok(())
                        }
                        (BinOpType::IntEqual, false) | (BinOpType::IntNotEqual, true) => {
                            // lhs != rhs
                            if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                                let new_result = self.eval(rhs).add_not_equal_bound(&bitvec)?;
                                self.specialize_by_expression_result(rhs, new_result)?;
                            }
                            if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                                let new_result = self.eval(lhs).add_not_equal_bound(&bitvec)?;
                                self.specialize_by_expression_result(lhs, new_result)?;
                            }
                            // Also specialize cases of pointer comparisons
                            self.specialize_pointer_comparison(&BinOpType::IntNotEqual, lhs, rhs)?;
                            Ok(())
                        }
                        _ => panic!(),
                    }
                }
                BinOpType::IntSLess
                | BinOpType::IntLess
                | BinOpType::IntLessEqual
                | BinOpType::IntSLessEqual => {
                    use BinOpType::*;
                    let mut op = *op;
                    let (mut left_expr, mut right_expr) = (lhs, rhs);
                    if result_bitvec.is_zero() {
                        std::mem::swap(&mut left_expr, &mut right_expr);
                        op = match op {
                            IntSLess => IntSLessEqual,
                            IntSLessEqual => IntSLess,
                            IntLess => IntLessEqual,
                            IntLessEqual => IntLess,
                            _ => panic!(),
                        }
                    }
                    self.specialize_by_comparison_op(&op, left_expr, right_expr)
                }
                _ => {
                    let original_expression = Expression::BinOp {
                        lhs: Box::new(lhs.clone()),
                        op: *op,
                        rhs: Box::new(rhs.clone()),
                    };
                    if let Ok(interval) = self.eval(&original_expression).try_to_interval() {
                        if !interval.contains(&result_bitvec) {
                            Err(anyhow!("Unsatisfiable bound"))
                        } else {
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    /// If both `lhs` and `rhs` evaluate to pointers and `op` is a comparison operator that evaluates to `true`,
    /// specialize the input pointers accordingly.
    ///
    /// Note that the current implementation only specializes for `==` and `!=` operators
    /// and only if the pointers point to the same unique memory object.
    fn specialize_pointer_comparison(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
    ) -> Result<(), Error> {
        let (lhs_pointer, rhs_pointer) = (self.eval(lhs), self.eval(rhs));
        match (
            lhs_pointer.get_if_unique_target(),
            rhs_pointer.get_if_unique_target(),
        ) {
            (Some((lhs_id, lhs_offset)), Some((rhs_id, rhs_offset))) if lhs_id == rhs_id => {
                if !(self.memory.is_unique_object(lhs_id)?) {
                    // Since the pointers may or may not point to different instances referenced by the same ID we cannot compare them.
                    return Ok(());
                }
                if *op == BinOpType::IntEqual {
                    let specialized_offset = lhs_offset.clone().intersect(rhs_offset)?;
                    let specialized_domain: Data =
                        Data::from_target(lhs_id.clone(), specialized_offset);
                    self.specialize_by_expression_result(lhs, specialized_domain.clone())?;
                    self.specialize_by_expression_result(rhs, specialized_domain)?;
                } else if *op == BinOpType::IntNotEqual {
                    if let Ok(rhs_offset_bitvec) = rhs_offset.try_to_bitvec() {
                        let new_lhs_offset =
                            lhs_offset.clone().add_not_equal_bound(&rhs_offset_bitvec)?;
                        self.specialize_by_expression_result(
                            lhs,
                            Data::from_target(lhs_id.clone(), new_lhs_offset),
                        )?;
                    }
                    if let Ok(lhs_offset_bitvec) = lhs_offset.try_to_bitvec() {
                        let new_rhs_offset =
                            rhs_offset.clone().add_not_equal_bound(&lhs_offset_bitvec)?;
                        self.specialize_by_expression_result(
                            rhs,
                            Data::from_target(rhs_id.clone(), new_rhs_offset),
                        )?;
                    }
                }
            }
            _ => (), // Other cases not handled, since it depends on the meaning of pointer IDs, which may change in the future.
        }
        Ok(())
    }

    /// Try to restrict the input variables of the given comparison operation
    /// (signed and unsigned versions of `<` and `<=`)
    /// so that the comparison evaluates to `true`.
    fn specialize_by_comparison_op(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
    ) -> Result<(), Error> {
        use BinOpType::*;
        if let Ok(mut lhs_bound) = self.eval(lhs).try_to_bitvec() {
            match op {
                IntSLess => {
                    if lhs_bound == Bitvector::signed_max_value(lhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    lhs_bound += &Bitvector::one(lhs_bound.width());
                    let new_result = self.eval(rhs).add_signed_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntSLessEqual => {
                    let new_result = self.eval(rhs).add_signed_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntLess => {
                    if lhs_bound == Bitvector::unsigned_max_value(lhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    lhs_bound += &Bitvector::one(lhs_bound.width());
                    let new_result = self
                        .eval(rhs)
                        .add_unsigned_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntLessEqual => {
                    let new_result = self
                        .eval(rhs)
                        .add_unsigned_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                _ => panic!(),
            }
        }
        if let Ok(mut rhs_bound) = self.eval(rhs).try_to_bitvec() {
            match op {
                IntSLess => {
                    if rhs_bound == Bitvector::signed_min_value(rhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    rhs_bound -= &Bitvector::one(rhs_bound.width());
                    let new_result = self.eval(lhs).add_signed_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntSLessEqual => {
                    let new_result = self.eval(lhs).add_signed_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntLess => {
                    if rhs_bound == Bitvector::zero(rhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    rhs_bound -= &Bitvector::one(rhs_bound.width());
                    let new_result = self.eval(lhs).add_unsigned_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntLessEqual => {
                    let new_result = self.eval(lhs).add_unsigned_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                _ => panic!(),
            }
        }
        Ok(())
    }
}

impl AbstractDomain for State {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.stack_id, other.stack_id);
        let mut merged_register = BTreeMap::new();
        for (register, other_value) in other.register.iter() {
            if let Some(value) = self.register.get(register) {
                let merged_value = value.merge(other_value);
                if !merged_value.is_top() {
                    // We only have to keep non-*Top* elements.
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

    /// A state has no *Top* element
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a more compact json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
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
mod tests;
