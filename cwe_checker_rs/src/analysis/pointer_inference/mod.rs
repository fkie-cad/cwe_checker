use super::abstract_domain::*;
use super::graph::Graph;
use crate::bil::{BitSize, Expression};
use crate::prelude::*;
use crate::term::symbol::ExternSymbol;
use crate::term::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

mod data;
mod identifier;
mod object;
mod state;

use data::Data;
use identifier::*;
use object::AbstractObjectList;
use state::State;

pub fn run(project: &Project) {
    let context = Context::new(project);
    let mut fixpoint_computation = super::interprocedural_fixpoint::Computation::new(context, None);
    // TODO: Add starting nodes!
    // TODO: compute!
    // TODO: print results in some form!
    println!("It works!");
    todo!()
}

struct Context<'a> {
    graph: Graph<'a>,
    project: &'a Project,
    extern_symbol_map: BTreeMap<Tid, &'a ExternSymbol>,
}

impl<'a> Context<'a> {
    pub fn new(project: &Project) -> Context {
        let mut extern_symbol_map = BTreeMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }
        let extern_symbol_tid_set: HashSet<Tid> = project.program.term.extern_symbols.iter().map(|symb| {symb.tid.clone()}).collect();
        let graph = super::graph::get_program_cfg(&project.program, extern_symbol_tid_set);
        Context {
            graph,
            project,
            extern_symbol_map,
        }
    }

    fn clear_stack_parameter(&self, state: &mut State, extern_call: &ExternSymbol) {
        for arg in &extern_call.arguments {
            match &arg.location {
                Expression::Var(_) => {},
                location_expression => {
                    let arg_size = arg.var.bitsize().expect("Encountered argument with unknown size");
                    let data_top = Data::new_top(arg_size);
                    *state = self.write_to_address(state, location_expression, data_top);
                }
            }
        }
    }

    /// Write the value given by data to the address one gets when evaluating the address expression.
    /// Return the modified state.
    fn write_to_address(&self, state: &State, address: &Expression, data: Data) -> State {
        if let Ok(Data::Pointer(pointer)) = state.eval(address) {
            let mut state = state.clone();
            state.store_value(&Data::Pointer(pointer), &data);
            return state;
        } else {
            // TODO: Implement proper error handling here.
            // Depending on the separation logic, the alternative to not changing the state would be to invaluate all knowledge about memory here.
            return state.clone();
        }
    }
}

impl<'a> super::interprocedural_fixpoint::Problem<'a> for Context<'a> {
    type Value = State;

    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Self::Value {
        // TODO: handle loads in the right hand side expression for their side effects!
        match &def.term.rhs {
            Expression::Store {
                memory: _,
                address,
                value,
                endian: _,
                size,
            } => {
                let data = state.eval(value).unwrap_or(Data::new_top(*size));
                assert_eq!(data.bitsize(), *size);
                // TODO: At the moment, both memory and endianness are ignored. Change that!
                return self.write_to_address(state, address, data);
            }
            expression => {
                let mut register = state.register.clone();
                // TODO: error messages while evaluating instructions are ignored at the moment.
                // These should be somehow made visible for the user or for debug purposes
                register.insert(
                    def.term.lhs.name.clone(),
                    state
                        .eval(&expression)
                        .unwrap_or(Data::new_top(def.term.lhs.bitsize().unwrap())),
                );
                State {
                    register,
                    ..state.clone()
                }
            }
        }
    }

    fn update_jump(
        &self,
        value: &State,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
    ) -> Option<State> {
        // TODO: Implement some real specialization of conditionals!
        Some(value.clone())
    }

    fn update_call(
        &self,
        state: &State,
        call_term: &Term<Jmp>,
        target_node: &super::graph::Node,
    ) -> State {
        let call = if let JmpKind::Call(ref call) = call_term.term.kind {
            call
        } else {
            panic!("Malformed control flow graph: Encountered call edge with a non-call jump term.")
        };
        let stack_offset_domain = self.get_current_stack_offset(state);

        if let Label::Direct(ref callee_tid) = call.target {
            let callee_stack_id = AbstractIdentifier::new(
                callee_tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let new_caller_stack_id = AbstractIdentifier::new(
                call_term.tid.clone(),
                AbstractLocation::from_var(&self.project.stack_pointer_register).unwrap(),
            );
            let stack_offset_adjustment = -stack_offset_domain.clone();
            let address_bitsize = self.project.stack_pointer_register.bitsize().unwrap();

            let mut callee_state = state.clone();
            // Replace the caller stack id with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id to avoid confusing caller and callee stack ids in case of recursive calls.
            callee_state.replace_abstract_id(
                &state.stack_id,
                &new_caller_stack_id,
                &stack_offset_adjustment,
            );
            // set the new stack_id
            callee_state.stack_id = new_caller_stack_id.clone();
            // add a new memory object for the callee stack frame
            callee_state.memory.add_abstract_object(
                callee_stack_id,
                Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap()).into(),
                object::ObjectType::Stack,
                address_bitsize,
            );
            // set the list of caller stack ids to only this caller id
            callee_state.caller_ids = BTreeSet::new();
            callee_state.caller_ids.insert(new_caller_stack_id.clone());
            // remove non-referenced objects from the state
            callee_state.remove_unreferenced_objects();

            return callee_state;
        } else {
            panic!("Indirect call edges not yet supported.")
            // TODO: Support indirect call edges!
        }
    }

    fn update_return(
        &self,
        state_before_return: &State,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
    ) -> Option<State> {
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

        let mut state_after_return = state_before_return.clone();
        state_after_return.replace_abstract_id(
            &caller_stack_id,
            original_caller_stack_id,
            &stack_offset_on_call,
        );
        state_after_return.replace_abstract_id(
            callee_stack_id,
            original_caller_stack_id,
            &stack_offset_on_call,
        ); // TODO: check correctness with unit tests!
        state_after_return.stack_id = original_caller_stack_id.clone();
        state_after_return.caller_ids = state_before_call.caller_ids.clone();
        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();
        // TODO: Check that callee objects can actually be forgotten! If not, adjust handling of referenced objects in tracked memory.
        // Or alternatively try to merge abstract ids of untracked objects?

        // TODO: In theory all references to the callee stack frame are deleted, thus the callee stack frame gets deleted by remove_unreferenced_objects.
        // Check that!
        // Also, I need to detect and report cases where pointers to objects on the callee stack get returned, as this has its own CWE number!
        Some(state_after_return)
    }

    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut new_state = state.clone();
        let call_target = match &call.term.kind {
            JmpKind::Call(call_inner) => &call_inner.target,
            _ => panic!("Malformed control flow graph encountered."),
        };
        // Clear non-callee-saved registers from the state
        for register in state.register.keys() {
            if self.project.callee_saved_registers.iter().find(|reg_name| {reg_name == &register}).is_none() {
                new_state.register.remove(register);
            }
        }
        match call_target {
            Label::Direct(tid) => {
                if let Some(extern_symbol) = self.extern_symbol_map.get(tid) {
                    // TODO: Replace the hardcoded symbol matching by something configurable in config.json!
                    // TODO: This implementation ignores that allocation functions may return Null,
                    // since this is not yet representable in the state object.
                    match extern_symbol.name.as_str() {
                        "malloc" | "calloc" | "realloc" | "xmalloc" => {
                            if let Ok(return_register) = get_return_register(extern_symbol) {
                                let object_id = AbstractIdentifier::new(
                                    call.tid.clone(),
                                    AbstractLocation::from_var(return_register).unwrap(),
                                );
                                let address_bitsize =
                                    self.project.stack_pointer_register.bitsize().unwrap();
                                new_state.memory.add_abstract_object(
                                    object_id.clone(),
                                    Bitvector::zero((address_bitsize as usize).into()).into(),
                                    object::ObjectType::Heap,
                                    address_bitsize,
                                );
                                let pointer = data::PointerDomain::new(object_id, Bitvector::zero((address_bitsize as usize).into()).into());
                                new_state.register.insert(return_register.name.clone(), pointer.into());
                                return Some(new_state);
                            } else {
                                // We cannot track the new object, since we do not know where to store the pointer to it.
                                // TODO: Return a diagnostics message to the user here.
                                return Some(new_state);
                            }
                        }
                        "free" => {
                            if let Ok(parameter_register) = get_parameter_register(extern_symbol) {
                                if let Ok(memory_object_pointer) = state.eval(&Expression::Var(parameter_register.clone())) {
                                    if let Data::Pointer(pointer) = memory_object_pointer {
                                        new_state.mark_mem_object_as_freed(&pointer);
                                    } // TODO: add diagnostics for else case
                                    return Some(new_state);
                                } else {
                                    // TODO: add diagnostics message for the user here
                                    return Some(new_state)
                                }
                            } else {
                                // We do not know which memory object to free
                                // TODO: Add a diagnostics message for the user here
                                return Some(new_state);
                            }
                        },
                        _ => {
                            self.clear_stack_parameter(&mut new_state, extern_symbol);
                            let mut possible_referenced_ids = BTreeSet::new();
                            if extern_symbol.arguments.len() == 0 {
                                // TODO: We assume here that we do not know the parameters and approximate them by all parameter registers.
                                // This approximation is wrong if the function is known but has neither parameters nor return values.
                                // We need to somehow distinguish these two cases.
                                for parameter_register_name in self.project.parameter_registers.iter() {
                                    if let Some(register_value) = state.register.get(parameter_register_name) {
                                        possible_referenced_ids.append(&mut register_value.referenced_ids());
                                    }
                                }
                            } else {
                                for parameter in extern_symbol.arguments.iter().filter(|arg| {arg.intent.is_input()}) {
                                    if let Ok(data) = state.eval(&parameter.location) {
                                        possible_referenced_ids.append(&mut data.referenced_ids());
                                    }
                                }
                            }
                            state.add_recursively_referenced_ids_to_id_set(&mut possible_referenced_ids);
                            // Delete content of all referenced objects, as the function may write to them.
                            for id in possible_referenced_ids.iter() {
                                new_state.memory.mark_mem_object_as_untracked(id, &possible_referenced_ids);
                            }
                            return Some(new_state);
                        },
                    }
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            Label::Indirect(_) => unimplemented!(), // Right now this case should not exist. Decide how to handle only after it can actually occur.
        }
    }

    fn specialize_conditional(
        &self,
        value: &State,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<State> {
        // TODO: implement some real specialization of conditionals!
        Some(value.clone())
    }
}

impl<'a> Context<'a> {
    fn get_current_stack_offset(&self, state: &State) -> BitvectorDomain {
        if let Data::Pointer(ref stack_pointer) =
            state.register[&self.project.stack_pointer_register.name]
        {
            if stack_pointer.iter_targets().len() == 1 {
                // TODO: add sanity check that the stack id is the expected id
                let (_stack_id, stack_offset_domain) = stack_pointer.iter_targets().next().unwrap();
                stack_offset_domain.clone()
            } else {
                BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
            }
        } else {
            BitvectorDomain::new_top(self.project.stack_pointer_register.bitsize().unwrap())
        }
    }
}

// TODO: This should be a method of ExternSymbol
/// Returns the return register of an extern symbol.
/// This function does not work correctly if there is more than one return register.
fn get_return_register(
    extern_symbol: &ExternSymbol,
) -> Result<&crate::bil::variable::Variable, Error> {
    let return_arg = extern_symbol
        .arguments
        .iter()
        .find(|arg| arg.intent.is_output())
        .ok_or(anyhow!("No return register"))?;
    match &return_arg.location {
        Expression::Var(var) => Ok(var),
        _ => Err(anyhow!("Return location is not a register"))?,
    }
}

// TODO: This should be a method of ExternSymbol
/// returns the parameter register of an extern symbol.
/// This function does not work correctly if there is more than one paramter register
fn get_parameter_register(
    extern_symbol: &ExternSymbol,
) -> Result<&crate::bil::variable::Variable, Error> {
    let param_arg = extern_symbol
        .arguments
        .iter()
        .find(|arg| arg.intent.is_input())
        .ok_or(anyhow!("No parameter register"))?;
    match &param_arg.location {
        Expression::Var(var) => Ok(var),
        _ => Err(anyhow!("Parameter location is not a register"))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        unimplemented!()
    }
}
