use super::*;
use std::collections::HashSet;

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the underlying graph on which the analysis operates.
    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    /// Merge two state values.
    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    /// Update the state according to the effects of the given `Def` term.
    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        // first check for use-after-frees
        if state.contains_access_of_dangling_memory(&def.term) {
            let warning = CweWarning {
                name: "CWE416".to_string(),
                version: VERSION.to_string(),
                addresses: vec![def.tid.address.clone()],
                tids: vec![format!("{}", def.tid)],
                symbols: Vec::new(),
                other: Vec::new(),
                description: format!(
                    "(Use After Free) Access through a dangling pointer at {}",
                    def.tid.address
                ),
            };
            let _ = self.log_collector.send(LogThreadMsg::Cwe(warning));
        }
        // check for out-of-bounds memory access
        if state.contains_out_of_bounds_mem_access(&def.term, self.runtime_memory_image) {
            let (warning_name, warning_description) = match def.term {
                Def::Load { .. } => (
                    "CWE125",
                    format!(
                        "(Out-of-bounds Read) Memory load at {} may be out of bounds",
                        def.tid.address
                    ),
                ),
                Def::Store { .. } => (
                    "CWE787",
                    format!(
                        "(Out-of-bounds Write) Memory write at {} may be out of bounds",
                        def.tid.address
                    ),
                ),
                Def::Assign { .. } => panic!(),
            };
            let warning = CweWarning {
                name: warning_name.to_string(),
                version: VERSION.to_string(),
                addresses: vec![def.tid.address.clone()],
                tids: vec![format!("{}", def.tid)],
                symbols: Vec::new(),
                other: Vec::new(),
                description: warning_description,
            };
            let _ = self.log_collector.send(LogThreadMsg::Cwe(warning));
        }

        match &def.term {
            Def::Store { address, value } => {
                let mut new_state = state.clone();
                self.log_debug(
                    new_state.handle_store(address, value, self.runtime_memory_image),
                    Some(&def.tid),
                );
                Some(new_state)
            }
            Def::Assign { var, value } => {
                let mut new_state = state.clone();
                new_state.handle_register_assign(var, value);
                Some(new_state)
            }
            Def::Load { var, address } => {
                let mut new_state = state.clone();
                self.log_debug(
                    new_state.handle_load(var, address, &self.runtime_memory_image),
                    Some(&def.tid),
                );
                Some(new_state)
            }
        }
    }

    /// Update the state according to the effects of the given `Jmp` term.
    /// Right now the state is not changed.
    fn update_jump(
        &self,
        value: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        let new_value = value.clone();
        Some(new_value)
    }

    /// Update the state according to the effects of the given `Call` term.
    /// The resulting state is the state at the start of the call target function.
    fn update_call(
        &self,
        state: &State,
        call_term: &Term<Jmp>,
        _target_node: &crate::analysis::graph::Node,
    ) -> Option<State> {
        if let Jmp::Call {
            target: ref callee_tid,
            return_: _,
        } = call_term.term
        {
            let callee_stack_id = AbstractIdentifier::new(
                callee_tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let new_caller_stack_id = AbstractIdentifier::new(
                call_term.tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let stack_offset_adjustment = self.get_current_stack_offset(state);
            let address_bytesize = self.project.stack_pointer_register.size;

            let mut callee_state = state.clone();
            // Remove virtual register since they do no longer exist in the callee
            callee_state.remove_virtual_register();
            // Remove callee-saved register, since the callee should not use their values anyway.
            // This should prevent recursive references to all stack frames in the call tree
            // since the source for it, the stack frame base pointer, is callee-saved.
            if let Some(cconv) = self.project.get_standard_calling_convention() {
                // Note that this may lead to analysis errors if the function uses another calling convention.
                callee_state.remove_callee_saved_register(cconv);
            }

            // Set the lower index bound for the caller stack frame.
            callee_state
                .memory
                .set_lower_index_bound(&state.stack_id, &stack_offset_adjustment);
            // Replace the caller stack ID with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id
            // to avoid confusing caller and callee stack ids in case of recursive calls.
            callee_state.replace_abstract_id(
                &state.stack_id,
                &new_caller_stack_id,
                &stack_offset_adjustment,
            );
            // add a new memory object for the callee stack frame
            callee_state.memory.add_abstract_object(
                callee_stack_id.clone(),
                Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
                ObjectType::Stack,
                address_bytesize,
            );
            // set the new stack_id
            callee_state.stack_id = callee_stack_id.clone();
            // Set the stack pointer register to the callee stack id.
            // At the beginning of a function this is the only known pointer to the new stack frame.
            callee_state.set_register(
                &self.project.stack_pointer_register,
                PointerDomain::new(
                    callee_stack_id.clone(),
                    Bitvector::zero(apint::BitWidth::from(address_bytesize)).into(),
                )
                .into(),
            );
            // set the list of caller stack ids to only this caller id
            callee_state.caller_stack_ids = BTreeSet::new();
            callee_state.caller_stack_ids.insert(new_caller_stack_id);
            // Remove non-referenced objects and objects, only the caller knows about, from the state.
            callee_state.ids_known_to_caller = BTreeSet::new();
            callee_state.remove_unreferenced_objects();
            // all remaining objects, except for the callee stack id, are also known to the caller
            callee_state.ids_known_to_caller = callee_state.memory.get_all_object_ids();
            callee_state.ids_known_to_caller.remove(&callee_stack_id);

            Some(callee_state)
        } else if let Jmp::CallInd { .. } = call_term.term {
            panic!("Indirect call edges not yet supported.")
        } else {
            panic!("Malformed control flow graph: Call edge was not a call.")
        }
    }

    /// Update the state according to the effects of the given return instruction.
    /// The `state_before_call` is used to reconstruct caller-specific information like the caller stack frame.
    fn update_return(
        &self,
        state_before_return: Option<&State>,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
    ) -> Option<State> {
        // TODO: For the long term we may have to replace the IDs representing callers with something
        // that identifies the edge of the call and not just the callsite.
        // When indirect calls are handled, the callsite alone is not a unique identifier anymore.
        // This may lead to confusion if both caller and callee have the same ID in their respective caller_stack_id sets.

        let (state_before_call, state_before_return) =
            match (state_before_call, state_before_return) {
                (Some(state_call), Some(state_return)) => (state_call, state_return),
                (Some(state_call), None) => {
                    if self.is_indirect_call_with_top_target(state_call, call_term) {
                        // We know nothing about the call target.
                        return self.handle_call_to_generic_unknown_function(&state_call);
                    } else {
                        // We know at least something about the call target.
                        // Since we don't have a return value,
                        // we assume that the called function may not return at all.
                        return None;
                    }
                }
                (None, Some(_state_return)) => return None, // we only return to functions with a value before the call to prevent returning to dead code
                (None, None) => return None,
            };

        let original_caller_stack_id = &state_before_call.stack_id;
        let caller_stack_id = AbstractIdentifier::new(
            call_term.tid.clone(),
            AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
        );
        let callee_stack_id = &state_before_return.stack_id;
        let stack_offset_on_call = self.get_current_stack_offset(state_before_call);

        // Detect possible information loss on the stack pointer and report it.
        if let Err(err) = self.detect_stack_pointer_information_loss_on_return(state_before_return)
        {
            self.log_debug(Err(err), Some(&return_term.tid));
            // This is an indicator of an analysis error
            // or a call to a non-returning extern function that was not marked as non-returning.
            return None;
        }

        // Check whether state_before_return actually knows the `caller_stack_id`.
        // If not, we are returning from a state that cannot correspond to this callsite.
        if !state_before_return
            .caller_stack_ids
            .contains(&caller_stack_id)
        {
            return None;
        }

        let mut state_after_return = state_before_return.clone();
        state_after_return.remove_virtual_register();
        // Remove the IDs of other callers not corresponding to this call
        state_after_return.remove_other_caller_stack_ids(&caller_stack_id);

        state_after_return.replace_abstract_id(
            &caller_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call.clone()),
        );
        state_after_return.merge_callee_stack_to_caller_stack(
            callee_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call),
        );
        state_after_return.stack_id = original_caller_stack_id.clone();
        state_after_return.caller_stack_ids = state_before_call.caller_stack_ids.clone();
        state_after_return.ids_known_to_caller = state_before_call.ids_known_to_caller.clone();

        state_after_return.readd_caller_objects(state_before_call);

        if let Some(cconv) = self.project.get_standard_calling_convention() {
            // Restore information about callee-saved register from the caller state.
            // TODO: Implement some kind of check to ensure that the callee adheres to the given calling convention!
            // The current workaround should be reasonably exact for programs written in C,
            // but may introduce a lot of errors
            // if the compiler often uses other calling conventions for internal function calls.
            state_after_return.restore_callee_saved_register(
                state_before_call,
                cconv,
                &self.project.stack_pointer_register,
            );
        }

        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();

        // remove the lower index bound of the stack frame
        state_after_return.memory.set_lower_index_bound(
            original_caller_stack_id,
            &IntervalDomain::new_top(self.project.stack_pointer_register.size),
        );

        Some(state_after_return)
    }

    /// Update the state according to the effect of a call to an extern symbol
    /// or an indirect call where nothing is known about the call target.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let call_target = match &call.term {
            Jmp::Call { target, .. } => target,
            Jmp::CallInd { .. } => {
                if self.is_indirect_call_with_top_target(state, call) {
                    // We know nothing about the call target.
                    return self.handle_call_to_generic_unknown_function(&state);
                } else {
                    return None;
                }
            }
            _ => panic!("Malformed control flow graph encountered."),
        };
        let mut new_state = state.clone();
        if let Some(extern_symbol) = self.extern_symbol_map.get(call_target) {
            // Generate a CWE-message if some argument is an out-of-bounds pointer.
            self.check_parameter_register_for_out_of_bounds_pointer(state, call, extern_symbol);
            // Clear non-callee-saved registers from the state.
            let cconv = extern_symbol.get_calling_convention(&self.project);
            new_state.clear_non_callee_saved_register(&cconv.callee_saved_register[..]);
            // Adjust stack register value (for x86 architecture).
            self.adjust_stack_register_on_extern_call(state, &mut new_state);
            // Check parameter for possible use-after-frees
            self.check_parameter_register_for_dangling_pointer(state, call, extern_symbol);

            match extern_symbol.name.as_str() {
                malloc_like_fn if self.allocation_symbols.iter().any(|x| x == malloc_like_fn) => {
                    Some(self.add_new_object_in_call_return_register(
                        new_state,
                        call,
                        extern_symbol,
                    ))
                }
                free_like_fn if self.deallocation_symbols.iter().any(|x| x == free_like_fn) => {
                    Some(self.mark_parameter_object_as_freed(state, new_state, call, extern_symbol))
                }
                _ => Some(self.handle_generic_extern_call(state, new_state, call, extern_symbol)),
            }
        } else {
            panic!("Extern symbol not found.");
        }
    }

    /// Update the state with the knowledge that some conditional evaluated to true or false.
    fn specialize_conditional(
        &self,
        value: &State,
        condition: &Expression,
        block_before_condition: &Term<Blk>,
        is_true: bool,
    ) -> Option<State> {
        let mut specialized_state = value.clone();
        if specialized_state
            .specialize_by_expression_result(condition, Bitvector::from_u8(is_true as u8).into())
            .is_err()
        {
            // State is unsatisfiable
            return None;
        }
        let mut modified_vars: HashSet<Variable> = HashSet::new();
        for def in block_before_condition.term.defs.iter().rev() {
            match &def.term {
                Def::Store { .. } => (),
                Def::Load { var, .. } => {
                    modified_vars.insert(var.clone());
                }
                Def::Assign {
                    var,
                    value: input_expr,
                } => {
                    if !modified_vars.contains(var) {
                        // Register is not modified again between the `Def` and the end of the block.
                        modified_vars.insert(var.clone());
                        if input_expr
                            .input_vars()
                            .into_iter()
                            .find(|input_var| modified_vars.contains(input_var))
                            .is_none()
                        {
                            // Values of input registers did not change between the `Def` and the end of the block.
                            let expr_result = specialized_state.get_register(var);
                            if specialized_state
                                .specialize_by_expression_result(input_expr, expr_result.clone())
                                .is_err()
                            {
                                // State is unsatisfiable
                                return None;
                            }
                        }
                    }
                }
            }
        }
        Some(specialized_state)
    }
}
