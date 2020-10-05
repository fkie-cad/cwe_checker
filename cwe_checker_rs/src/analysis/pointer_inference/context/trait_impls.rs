use super::*;

impl<'a> crate::analysis::interprocedural_fixpoint::Context<'a> for Context<'a> {
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
            self.cwe_collector.send(warning).unwrap();
        }

        match &def.term {
            Def::Store { address, value } => {
                let mut state = state.clone();
                self.log_debug(state.handle_store(address, value), Some(&def.tid));
                Some(state)
            }
            Def::Assign { var, value } => {
                let mut new_state = state.clone();
                self.log_debug(new_state.handle_register_assign(var, value), Some(&def.tid));
                Some(new_state)
            }
            Def::Load { var, address } => {
                let mut new_state = state.clone();
                self.log_debug(new_state.handle_load(var, address), Some(&def.tid));
                Some(new_state)
            }
        }
    }

    /// Update the state according to the effects of the given `Jmp` term.
    /// Right now the state is not changed,
    /// as specialization for conditional jumps is not implemented yet.
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
            callee_state.remove_virtual_register();
            // Replace the caller stack ID with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id to avoid confusing caller and callee stack ids in case of recursive calls.
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
        state_before_return: &State,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
    ) -> Option<State> {
        // TODO: For the long term we may have to replace the IDs representing callers with something
        // that identifies the edge of the call and not just the callsite.
        // When indirect calls are handled, the callsite alone is not a unique identifier anymore.
        // This may lead to confusion if both caller and callee have the same ID in their respective caller_stack_id sets.

        // we only return to functions with a value before the call to prevent returning to dead code
        let state_before_call = match state_before_call {
            Some(value) => value,
            None => return None,
        };
        let original_caller_stack_id = &state_before_call.stack_id;
        let caller_stack_id = AbstractIdentifier::new(
            call_term.tid.clone(),
            AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
        );
        let callee_stack_id = &state_before_return.stack_id;
        let stack_offset_on_call = self.get_current_stack_offset(state_before_call);

        // Detect possible information loss on the stack pointer and report it.
        self.detect_stack_pointer_information_loss_on_return(state_before_return, return_term);

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

        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();

        Some(state_after_return)
    }

    /// Update the state according to the effect of a call to an extern symbol.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut new_state = state.clone();
        let call_target = match &call.term {
            Jmp::Call { target, .. } => target,
            Jmp::CallInd { .. } => panic!("Indirect calls to extern symbols not yet supported."),
            _ => panic!("Malformed control flow graph encountered."),
        };
        // Clear non-callee-saved registers from the state.
        new_state.clear_non_callee_saved_register(&self.project.callee_saved_registers[..]);
        // On x86, remove the return address from the stack (other architectures pass the return address in a register, not on the stack).
        // Note that in some calling conventions the callee also clears function parameters from the stack.
        // We do not detect and handle these cases yet.
        let stack_register = &self.project.stack_pointer_register;
        let stack_pointer = state.get_register(stack_register).unwrap();
        match self.project.cpu_architecture.as_str() {
            "x86" | "x86_64" => {
                let offset = Bitvector::from_u64(stack_register.size.into())
                    .into_truncate(apint::BitWidth::from(stack_register.size))
                    .unwrap();
                new_state.set_register(
                    stack_register,
                    stack_pointer.bin_op(BinOpType::IntAdd, &offset.into()),
                );
            }
            _ => new_state.set_register(stack_register, stack_pointer),
        }
        if let Some(extern_symbol) = self.extern_symbol_map.get(call_target) {
            // Check parameter for possible use-after-frees
            self.check_parameter_register_for_dangling_pointer(state, call, extern_symbol);

            match extern_symbol.name.as_str() {
                "malloc" | "calloc" | "realloc" | "xmalloc" => {
                    self.add_new_object_in_call_return_register(new_state, call, extern_symbol)
                }
                "free" => {
                    self.mark_parameter_object_as_freed(state, new_state, call, extern_symbol)
                }
                _ => self.handle_generic_extern_call(state, new_state, call, extern_symbol),
            }
        } else {
            panic!("Extern symbol not found.");
        }
    }

    /// Update the state with the knowledge that some conditional evaluated to true or false.
    /// Currently not implemented, this function just returns the state as it is.
    fn specialize_conditional(
        &self,
        value: &State,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<State> {
        Some(value.clone())
    }
}
