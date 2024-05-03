use super::*;

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the underlying graph on which the analysis operates.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge two state values.
    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    /// Update the state according to the effects of the given `Def` term.
    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let mut new_state = state.clone();
        // check for null dereferences
        match new_state.check_def_for_null_dereferences(def) {
            Err(_) => {
                self.report_null_deref(&def.tid);
                return None;
            }
            Ok(true) => self.report_null_deref(&def.tid),
            Ok(false) => (), // no null dereference detected
        }

        match &def.term {
            Def::Store { address, value } => {
                self.log_debug(
                    new_state.handle_store(address, value, &self.project.runtime_memory_image),
                    Some(&def.tid),
                );
                Some(new_state)
            }
            Def::Assign { var, value } => {
                new_state.handle_register_assign(var, value);
                Some(new_state)
            }
            Def::Load { var, address } => {
                if !self.is_mips_gp_load_to_top_value(state, var, address) {
                    self.log_debug(
                        new_state.handle_load(var, address, &self.project.runtime_memory_image),
                        Some(&def.tid),
                    );
                }
                // Else we ignore the load and hope that the value still contained in the gp register is still correct.
                // This only works because gp is (incorrectly) marked as a callee-saved register.
                // FIXME: If the rest of the analysis becomes good enough so that this case is not common anymore,
                // we should log it.
                Some(new_state)
            }
        }
    }

    /// Update the state according to the effects of the given `Jmp` term.
    fn update_jump(
        &self,
        state: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        let new_state = state.clone();
        Some(new_state)
    }

    /// Update the state according to the effects of the given `Call` term.
    /// The resulting state is the state at the start of the call target function.
    fn update_call(
        &self,
        _state: &State,
        call_term: &Term<Jmp>,
        _target_node: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        if let Jmp::Call { .. } = call_term.term {
            // No information flows from caller to the callee in the analysis.
            None
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
        calling_convention_opt: &Option<String>,
    ) -> Option<State> {
        let (state_before_call, state_before_return) =
            match (state_before_call, state_before_return) {
                (Some(state_call), Some(state_return)) => (state_call, state_return),
                (Some(state_call), None) => {
                    if self.is_indirect_call_with_top_target(state_call, call_term) {
                        // We know nothing about the call target.
                        return self.handle_call_to_generic_unknown_function(state_call);
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

        let cconv = match self
            .project
            .get_specific_calling_convention(calling_convention_opt)
        {
            Some(cconv) => cconv,
            None => {
                // If we neither know the specific nor a default calling convention for the function,
                // then we treat it as a dead end in the control flow graph.
                return None;
            }
        };
        let callee_fn_sig = match self.fn_signatures.get(state_before_return.get_fn_tid()) {
            Some(fn_sig) => fn_sig,
            None => {
                let location = state_before_return.get_fn_tid();
                self.log_error(
                    Err(anyhow!(
                        "Internal function {} has no function signature.",
                        location
                    )),
                    Some(location),
                );
                return None;
            }
        };

        // Detect possible information loss on the stack pointer and report it.
        if let Err(err) = self.detect_stack_pointer_information_loss_on_return(state_before_return)
        {
            self.log_debug(Err(err), Some(&return_term.tid));
            // This is an indicator of an analysis error
            // or a call to a non-returning extern function that was not marked as non-returning.
            return None;
        }
        // Minimize the callee state and replace callee-originating object IDs whenever possible.
        let mut state_before_return = state_before_return.clone();
        state_before_return.minimize_before_return_instruction(callee_fn_sig, cconv);
        state_before_return.merge_mem_objects_with_unique_abstract_location(&call_term.tid);
        // Create a mapping of IDs from the callee to IDs that should be used in the caller.
        let id_map =
            self.create_callee_id_to_caller_data_map(state_before_call, &state_before_return);
        let callee_id_to_access_pattern_map =
            self.create_id_to_access_pattern_map(&state_before_return);
        // Identify caller IDs for which the callee analysis may be unsound for this callsite.
        let unsound_caller_ids =
            self.get_unsound_caller_ids(&id_map, &callee_id_to_access_pattern_map);
        // FIXME: Unsound caller IDs occur too often to log the cases right now.
        // We have to investigate the reasons for it (maybe too many parameters on the caller stack?)
        // and find better heuristics to prevent them poisoning the analysis soundness.

        let mut state_after_return = state_before_call.clone();
        // Adjust register values of state_after_return
        state_after_return.remove_non_callee_saved_register(cconv);
        self.adjust_stack_register_on_return_from_call(state_before_call, &mut state_after_return);
        for return_reg in cconv.get_all_return_register() {
            let mut return_value = state_before_return.get_register(return_reg);
            return_value.replace_all_ids(&id_map);
            if !return_value.is_top() {
                state_after_return.set_register(return_reg, return_value);
            }
        }
        // Merge or add memory objects from the callee to the caller state.
        for (callee_object_id, callee_object) in state_before_return.memory.iter() {
            if *callee_object_id == state_before_return.stack_id {
                // The callee stack frame does not exist anymore after return to the caller.
                continue;
            }
            if *callee_object_id == state_before_return.get_global_mem_id() {
                self.merge_non_nested_global_mem_from_callee(
                    &mut state_after_return,
                    callee_object,
                    &id_map,
                    callee_fn_sig,
                    &call_term.tid,
                );
                continue;
            }
            if Some(false)
                == callee_id_to_access_pattern_map
                    .get(callee_object_id)
                    .map(|access_pattern| access_pattern.is_mutably_dereferenced())
            {
                // We do not have to modify anything for parameter objects that are only read but not written to.
                continue;
            }
            let mut callee_object = callee_object.clone();
            callee_object.replace_ids(&id_map);

            if !callee_id_to_access_pattern_map.contains_key(callee_object_id) {
                // Add a callee object that does not correspond to a parameter to the caller or the stack of the callee.
                state_after_return
                    .memory
                    .insert(callee_object_id.clone(), callee_object);
            } else {
                // The callee object is a parameter object.
                self.log_debug(
                    state_after_return.add_param_object_from_callee(
                        callee_object,
                        id_map.get(callee_object_id).unwrap(),
                    ),
                    Some(&call_term.tid),
                );
            }
        }
        // Additionally assume arbitrary writes for every caller ID where the callee handling might be unsound.
        for id in &unsound_caller_ids {
            state_after_return
                .memory
                .assume_arbitrary_writes_to_object(id, &BTreeSet::new());
        }
        // Cleanup
        state_after_return.remove_unreferenced_objects();

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
                    return self.handle_call_to_generic_unknown_function(state);
                } else {
                    return None;
                }
            }
            _ => panic!("Malformed control flow graph encountered."),
        };
        let mut new_state = state.clone();
        if let Some(extern_symbol) = self.extern_symbol_map.get(call_target) {
            // Clear non-callee-saved registers from the state.
            let cconv = self.project.get_calling_convention(extern_symbol);
            new_state.clear_non_callee_saved_register(&cconv.callee_saved_register[..]);
            // Adjust stack register value (for x86 architecture).
            self.adjust_stack_register_on_return_from_call(state, &mut new_state);

            match extern_symbol.name.as_str() {
                "sscanf" => {
                    self.log_debug(
                        self.handle_params_of_sscanf_call(
                            state,
                            &mut new_state,
                            extern_symbol,
                            &call.tid,
                        ),
                        Some(&call.tid),
                    );
                    Some(new_state)
                }
                malloc_like_fn if self.allocation_symbols.iter().any(|x| x == malloc_like_fn) => {
                    Some(self.add_new_object_in_call_return_register(
                        new_state,
                        call,
                        extern_symbol,
                    ))
                }
                stubbed_fn
                    if self
                        .extern_fn_param_access_patterns
                        .contains_key(stubbed_fn) =>
                {
                    self.handle_parameter_access_for_stubbed_functions(
                        state,
                        &mut new_state,
                        extern_symbol,
                    );

                    let return_value =
                        self.compute_return_value_for_stubbed_function(state, extern_symbol);
                    new_state.set_register(&cconv.integer_return_register[0], return_value);

                    Some(new_state)
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
        state: &State,
        condition: &Expression,
        _block_before_condition: &Term<Blk>,
        is_true: bool,
    ) -> Option<State> {
        let mut specialized_state = state.clone();
        match specialized_state
            .specialize_by_expression_result(condition, Bitvector::from_u8(is_true as u8).into())
        {
            Ok(_) => Some(specialized_state),
            // State is unsatisfiable
            Err(_) => None,
        }
    }
}
