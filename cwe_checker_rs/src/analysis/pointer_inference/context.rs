use crate::analysis::abstract_domain::*;
use crate::analysis::graph::Graph;
use crate::analysis::interprocedural_fixpoint::{Computation, NodeValue};
use crate::bil::{Expression, Variable};
use crate::prelude::*;
use crate::term::symbol::ExternSymbol;
use crate::term::*;
use crate::utils::log::*;
use petgraph::graph::NodeIndex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::data::Data;
use super::identifier::*;
use super::state::State;

pub struct Context<'a> {
    pub graph: Graph<'a>,
    pub project: &'a Project,
    pub extern_symbol_map: BTreeMap<Tid, &'a ExternSymbol>,
    pub cwe_collector: crossbeam_channel::Sender<CweWarning>,
    pub log_collector: crossbeam_channel::Sender<LogMessage>,
}

impl<'a> Context<'a> {
    pub fn new(
        project: &Project,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
        log_collector: crossbeam_channel::Sender<LogMessage>,
    ) -> Context {
        let mut extern_symbol_map = BTreeMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }
        let extern_symbol_tid_set: HashSet<Tid> = project
            .program
            .term
            .extern_symbols
            .iter()
            .map(|symb| symb.tid.clone())
            .collect();
        let graph =
            crate::analysis::graph::get_program_cfg(&project.program, extern_symbol_tid_set);
        Context {
            graph,
            project,
            extern_symbol_map,
            cwe_collector,
            log_collector,
        }
    }

    pub fn log_debug<'_lt>(&self, result: Result<(), Error>, location: Option<&'_lt Tid>) {
        if let Err(err) = result {
            let log_message = LogMessage {
                text: format!("Pointer Inference: {}", err),
                level: LogLevel::Debug,
                location: location.cloned(),
            };
            self.log_collector.send(log_message).unwrap();
        }
    }
}

impl<'a> crate::analysis::interprocedural_fixpoint::Problem<'a> for Context<'a> {
    type Value = State;

    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    fn merge(&self, value1: &State, value2: &State) -> State {
        value1.merge(value2)
    }

    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Self::Value {
        // first check for use-after-frees
        if state.contains_access_of_dangling_memory(&def.term.rhs) {
            let warning = CweWarning {
                name: "CWE416".to_string(),
                version: "0.1".to_string(),
                addresses: vec![def.tid.address.clone()],
                tids: vec![format!("{}", def.tid)],
                symbols: Vec::new(),
                other: Vec::new(),
                description: format!(
                    "(Use after free) Access through a dangling pointer at {}",
                    def.tid.address
                ),
            };
            self.cwe_collector.send(warning).unwrap();
        }
        // TODO: handle loads in the right hand side expression for their side effects!
        match &def.term.rhs {
            Expression::Store { .. } => {
                let mut state = state.clone();
                self.log_debug(state.handle_store_exp(&def.term.rhs), Some(&def.tid));
                state
            }
            Expression::IfThenElse {
                condition,
                true_exp,
                false_exp,
            } => {
                // IfThenElse needs special handling, because it may encode conditional store instructions.
                let mut true_state = state.clone();
                if let Expression::Store { .. } = **true_exp {
                    self.log_debug(true_state.handle_store_exp(true_exp), Some(&def.tid));
                } else {
                    self.log_debug(
                        true_state.handle_register_assign(&def.term.lhs, true_exp),
                        Some(&def.tid),
                    );
                };
                let mut false_state = state.clone();
                if let Expression::Store { .. } = **false_exp {
                    self.log_debug(false_state.handle_store_exp(false_exp), Some(&def.tid));
                } else {
                    self.log_debug(
                        false_state.handle_register_assign(&def.term.lhs, false_exp),
                        Some(&def.tid),
                    );
                };
                match state.eval(condition) {
                    Ok(Data::Value(cond)) => {
                        if cond == Bitvector::from_bit(true).into() {
                            true_state
                        } else if cond == Bitvector::from_bit(false).into() {
                            false_state
                        } else {
                            panic!("IfThenElse with wrong condition bitsize encountered")
                        }
                    }
                    Ok(_) => true_state.merge(&false_state),
                    Err(err) => panic!("IfThenElse-Condition evaluation failed: {}", err),
                }
            }
            expression => {
                let mut new_state = state.clone();
                self.log_debug(
                    new_state.handle_register_assign(&def.term.lhs, expression),
                    Some(&def.tid),
                );
                new_state
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
        let mut new_value = value.clone();
        new_value.remove_virtual_register();
        Some(new_value)
    }

    fn update_call(
        &self,
        state: &State,
        call_term: &Term<Jmp>,
        target_node: &crate::analysis::graph::Node,
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
            let stack_offset_adjustment = stack_offset_domain.clone();
            let address_bitsize = self.project.stack_pointer_register.bitsize().unwrap();

            let mut callee_state = state.clone();
            callee_state.remove_virtual_register();
            // Replace the caller stack id with one determined by the call instruction.
            // This has to be done *before* adding the new callee stack id to avoid confusing caller and callee stack ids in case of recursive calls.
            callee_state.replace_abstract_id(
                &state.stack_id,
                &new_caller_stack_id,
                &stack_offset_adjustment,
            );
            // add a new memory object for the callee stack frame
            callee_state.memory.add_abstract_object(
                callee_stack_id.clone(),
                Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap()).into(),
                super::object::ObjectType::Stack,
                address_bitsize,
            );
            // set the new stack_id
            callee_state.stack_id = callee_stack_id.clone();
            // Set the stack pointer register to the callee stack id.
            // At the beginning of a function this is the only known pointer to the new stack frame.
            callee_state.set_register(
                &self.project.stack_pointer_register,
                super::data::PointerDomain::new(
                    callee_stack_id,
                    Bitvector::zero(apint::BitWidth::new(address_bitsize as usize).unwrap()).into(),
                )
                .into(),
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
        state_after_return.remove_virtual_register();
        state_after_return.replace_abstract_id(
            &caller_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call.clone()),
        );
        state_after_return.merge_callee_stack_to_caller_stack(
            callee_stack_id,
            original_caller_stack_id,
            &(-stack_offset_on_call.clone()),
        );
        state_after_return.stack_id = original_caller_stack_id.clone();
        state_after_return.caller_ids = state_before_call.caller_ids.clone();
        // remove non-referenced objects from the state
        state_after_return.remove_unreferenced_objects();

        // TODO: I need to detect and report cases where pointers to objects on the callee stack get returned, as this has its own CWE number!
        // Detect and report cases, where knowledge about the offset of the stack pointer gets lost on return!
        // Maybe add a fallback repair mechanism in these cases.
        Some(state_after_return)
    }

    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut new_state = state.clone();
        let call_target = match &call.term.kind {
            JmpKind::Call(call_inner) => &call_inner.target,
            _ => panic!("Malformed control flow graph encountered."),
        };
        // Clear non-callee-saved registers from the state.
        new_state.clear_non_callee_saved_register(&self.project.callee_saved_registers[..]);
        // Set the stack register value.
        // TODO: This is wrong if the extern call clears more from the stack than just the return address.
        // TODO: a check on validity of the return address could also be useful here.
        let stack_register = &self.project.stack_pointer_register;
        {
            let stack_pointer = state.get_register(stack_register).unwrap();
            let offset = Bitvector::from_u8(8)
                .into_zero_extend(stack_register.bitsize().unwrap() as usize)
                .unwrap();
            new_state.set_register(
                stack_register,
                stack_pointer.bin_op(crate::bil::BinOpType::PLUS, &Data::bitvector(offset)),
            );
        }

        match call_target {
            Label::Direct(tid) => {
                if let Some(extern_symbol) = self.extern_symbol_map.get(tid) {
                    // TODO: Replace the hardcoded symbol matching by something configurable in config.json!
                    // TODO: This implementation ignores that allocation functions may return Null,
                    // since this is not yet representable in the state object.

                    // Check all parameter register for dangling pointers and report possible use-after-free if one is found.
                    for argument in extern_symbol
                        .arguments
                        .iter()
                        .filter(|arg| arg.intent.is_input())
                    {
                        match state.eval(&argument.location) {
                            Ok(value) => {
                                if state.memory.is_dangling_pointer(&value) {
                                    let warning = CweWarning {
                                        name: "CWE416".to_string(),
                                        version: "0.1".to_string(),
                                        addresses: vec![call.tid.address.clone()],
                                        tids: vec![format!("{}", call.tid)],
                                        symbols: Vec::new(),
                                        other: Vec::new(),
                                        description: format!("(Use after free) Call to {} may access freed memory at {}", extern_symbol.name, call.tid.address),
                                    };
                                    self.cwe_collector.send(warning).unwrap();
                                }
                            }
                            Err(err) => self.log_debug(
                                Err(err.context(format!(
                                    "Function argument expression {:?} could not be evaluated",
                                    argument.location
                                ))),
                                Some(&call.tid),
                            ),
                        }
                    }

                    match extern_symbol.name.as_str() {
                        "malloc" | "calloc" | "realloc" | "xmalloc" => {
                            if let Ok(return_register) = extern_symbol.get_unique_return_register()
                            {
                                let object_id = AbstractIdentifier::new(
                                    call.tid.clone(),
                                    AbstractLocation::from_var(return_register).unwrap(),
                                );
                                let address_bitsize =
                                    self.project.stack_pointer_register.bitsize().unwrap();
                                new_state.memory.add_abstract_object(
                                    object_id.clone(),
                                    Bitvector::zero((address_bitsize as usize).into()).into(),
                                    super::object::ObjectType::Heap,
                                    address_bitsize,
                                );
                                let pointer = super::data::PointerDomain::new(
                                    object_id,
                                    Bitvector::zero((address_bitsize as usize).into()).into(),
                                );
                                new_state.set_register(return_register, pointer.into());
                                return Some(new_state);
                            } else {
                                // We cannot track the new object, since we do not know where to store the pointer to it.
                                // TODO: Return a diagnostics message to the user here.
                                return Some(new_state);
                            }
                        }
                        "free" => {
                            if let Ok(parameter_register) =
                                extern_symbol.get_unique_parameter_register()
                            {
                                if let Ok(memory_object_pointer) =
                                    state.eval(&Expression::Var(parameter_register.clone()))
                                {
                                    if let Data::Pointer(pointer) = memory_object_pointer {
                                        if let Err(possible_double_free_object_ids) =
                                            new_state.mark_mem_object_as_freed(&pointer)
                                        {
                                            let warning = CweWarning {
                                                name: "CWE415".to_string(),
                                                version: "0.1".to_string(),
                                                addresses: vec![call.tid.address.clone()],
                                                tids: vec![format!("{}", call.tid)],
                                                symbols: Vec::new(),
                                                other: vec![possible_double_free_object_ids.into_iter().map(|id| {format!("{}", id)}).collect()],
                                                description: format!("(Double Free) Object may have been freed before at {}", call.tid.address),
                                            };
                                            self.cwe_collector.send(warning).unwrap();
                                        }
                                    } // TODO: add diagnostics for else case
                                    new_state.remove_unreferenced_objects();
                                    return Some(new_state);
                                } else {
                                    // TODO: add diagnostics message for the user here
                                    return Some(new_state);
                                }
                            } else {
                                // We do not know which memory object to free
                                // TODO: Add a diagnostics message for the user here
                                return Some(new_state);
                            }
                        }
                        _ => {
                            self.log_debug(
                                new_state.clear_stack_parameter(extern_symbol),
                                Some(&call.tid),
                            );
                            let mut possible_referenced_ids = BTreeSet::new();
                            if extern_symbol.arguments.len() == 0 {
                                // TODO: We assume here that we do not know the parameters and approximate them by all parameter registers.
                                // This approximation is wrong if the function is known but has neither parameters nor return values.
                                // We need to somehow distinguish these two cases.
                                // TODO: We need to cleanup stack memory below the current position of the stack pointer.
                                for parameter_register_name in
                                    self.project.parameter_registers.iter()
                                {
                                    if let Some(register_value) =
                                        state.get_register_by_name(parameter_register_name)
                                    {
                                        possible_referenced_ids
                                            .append(&mut register_value.referenced_ids());
                                    }
                                }
                            } else {
                                for parameter in extern_symbol
                                    .arguments
                                    .iter()
                                    .filter(|arg| arg.intent.is_input())
                                {
                                    if let Ok(data) = state.eval(&parameter.location) {
                                        possible_referenced_ids.append(&mut data.referenced_ids());
                                    }
                                }
                            }
                            possible_referenced_ids = state
                                .add_recursively_referenced_ids_to_id_set(possible_referenced_ids);
                            // Delete content of all referenced objects, as the function may write to them.
                            for id in possible_referenced_ids.iter() {
                                new_state
                                    .memory
                                    .mark_mem_object_as_untracked(id, &possible_referenced_ids);
                            }
                            return Some(new_state);
                        }
                    }
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            Label::Indirect(_) => unimplemented!("Handling of indirect edges not yet implemented"), // Right now this case should not exist. Decide how to handle only after it can actually occur.
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
        if let Ok(Data::Pointer(ref stack_pointer)) =
            state.get_register(&self.project.stack_pointer_register)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bil::variable::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(time: &str, reg_name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new(time),
            AbstractLocation::Register(reg_name.to_string(), 64),
        )
    }

    fn mock_extern_symbol(name: &str) -> ExternSymbol {
        use crate::bil;
        let arg = Arg {
            var: register("RAX"),
            location: bil::Expression::Var(register("RAX")),
            intent: ArgIntent::Both,
        };
        ExternSymbol {
            tid: Tid::new("extern_".to_string() + name),
            address: "somewhere".into(),
            name: name.into(),
            calling_convention: None,
            arguments: vec![arg],
        }
    }

    fn register(name: &str) -> Variable {
        Variable {
            name: name.into(),
            type_: crate::bil::variable::Type::Immediate(64),
            is_temp: false,
        }
    }

    fn call_term(target_name: &str) -> Term<Jmp> {
        let call = Call {
            target: Label::Direct(Tid::new(target_name)),
            return_: None,
        };
        Term {
            tid: Tid::new(format!("call_{}", target_name)),
            term: Jmp {
                condition: None,
                kind: JmpKind::Call(call),
            },
        }
    }

    fn mock_project() -> Project {
        let program = Program {
            subs: Vec::new(),
            extern_symbols: vec![
                mock_extern_symbol("malloc"),
                mock_extern_symbol("free"),
                mock_extern_symbol("other"),
            ],
            entry_points: Vec::new(),
        };
        let program_term = Term {
            tid: Tid::new("program"),
            term: program,
        };
        Project {
            program: program_term,
            cpu_architecture: "mock_arch".to_string(),
            stack_pointer_register: register("RSP"),
            callee_saved_registers: vec!["callee_saved_reg".to_string()],
            parameter_registers: vec!["RAX".to_string()],
        }
    }

    #[test]
    fn context_problem_implementation() {
        use crate::analysis::interprocedural_fixpoint::Problem;
        use crate::analysis::pointer_inference::data::*;
        use crate::bil::*;
        use Expression::*;

        let project = mock_project();
        let (cwe_sender, _cwe_receiver) = crossbeam_channel::unbounded();
        let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
        let context = Context::new(&project, cwe_sender, log_sender);
        let mut state = State::new(&register("RSP"), Tid::new("main"));

        let def = Term {
            tid: Tid::new("def"),
            term: Def {
                lhs: register("RSP"),
                rhs: BinOp {
                    op: BinOpType::PLUS,
                    lhs: Box::new(Var(register("RSP"))),
                    rhs: Box::new(Const(Bitvector::from_i64(-16))),
                },
            },
        };
        let store_term = Term {
            tid: Tid::new("store"),
            term: Def {
                lhs: register("memory"), // technically false, but not checked at the moment
                rhs: Store {
                    address: Box::new(Var(register("RSP"))),
                    endian: Endianness::LittleEndian,
                    memory: Box::new(Var(register("memory"))), // This is technically false, but the field is ignored at the moment
                    value: Box::new(Const(Bitvector::from_i64(42))),
                    size: 64,
                },
            },
        };

        // test update_def
        state = context.update_def(&state, &def);
        let stack_pointer = Data::Pointer(PointerDomain::new(new_id("main", "RSP"), bv(-16)));
        assert_eq!(state.eval(&Var(register("RSP"))).unwrap(), stack_pointer);
        state = context.update_def(&state, &store_term);

        // Test update_call
        let target_block = Term {
            tid: Tid::new("func_start"),
            term: Blk {
                defs: Vec::new(),
                jmps: Vec::new(),
            },
        };
        let target_node = crate::analysis::graph::Node::BlkStart(&target_block);
        let call = call_term("func");
        let mut callee_state = context.update_call(&state, &call, &target_node);
        assert_eq!(callee_state.stack_id, new_id("func", "RSP"));
        assert_eq!(callee_state.caller_ids.len(), 1);
        assert_eq!(
            callee_state.caller_ids.iter().next().unwrap(),
            &new_id("call_func", "RSP")
        );

        callee_state
            .memory
            .set_value(
                PointerDomain::new(new_id("func", "RSP"), bv(-30)),
                Data::Value(bv(33).into()),
            )
            .unwrap();
        let return_state = context
            .update_return(&callee_state, Some(&state), &call)
            .unwrap();
        assert_eq!(return_state.stack_id, new_id("main", "RSP"));
        assert_eq!(return_state.caller_ids, BTreeSet::new());
        assert_eq!(
            return_state.memory.get_internal_id_map(),
            state.memory.get_internal_id_map()
        );
        assert_eq!(
            return_state.get_register(&register("RSP")).unwrap(),
            state.get_register(&register("RSP")).unwrap()
        );

        state.set_register(&register("callee_saved_reg"), Data::Value(bv(13)));
        state.set_register(&register("other_reg"), Data::Value(bv(14)));

        let malloc = call_term("extern_malloc");
        let mut state_after_malloc = context.update_call_stub(&state, &malloc).unwrap();
        assert_eq!(
            state_after_malloc.get_register(&register("RAX")).unwrap(),
            Data::Pointer(PointerDomain::new(
                new_id("call_extern_malloc", "RAX"),
                bv(0)
            ))
        );
        assert_eq!(state_after_malloc.memory.get_num_objects(), 2);
        assert_eq!(
            state_after_malloc.get_register(&register("RSP")).unwrap(),
            state
                .get_register(&register("RSP"))
                .unwrap()
                .bin_op(BinOpType::PLUS, &Data::Value(bv(8)))
        );
        assert_eq!(
            state_after_malloc
                .get_register(&register("callee_saved_reg"))
                .unwrap(),
            Data::Value(bv(13))
        );
        assert!(state_after_malloc
            .get_register(&register("other_reg"))
            .unwrap()
            .is_top());

        state_after_malloc.set_register(
            &register("callee_saved_reg"),
            Data::Pointer(PointerDomain::new(
                new_id("call_extern_malloc", "RAX"),
                bv(0),
            )),
        );
        let free = call_term("extern_free");
        let state_after_free = context
            .update_call_stub(&state_after_malloc, &free)
            .unwrap();
        assert!(state_after_free
            .get_register(&register("RAX"))
            .unwrap()
            .is_top());
        assert_eq!(state_after_free.memory.get_num_objects(), 2);
        assert_eq!(
            state_after_free
                .get_register(&register("callee_saved_reg"))
                .unwrap(),
            Data::Pointer(PointerDomain::new(
                new_id("call_extern_malloc", "RAX"),
                bv(0)
            ))
        );

        let other_extern_fn = call_term("extern_other");
        let state_after_other_fn = context.update_call_stub(&state, &other_extern_fn).unwrap();

        assert_eq!(
            state_after_other_fn.get_register(&register("RSP")).unwrap(),
            state
                .get_register(&register("RSP"))
                .unwrap()
                .bin_op(BinOpType::PLUS, &Data::Value(bv(8)))
        );
        assert_eq!(
            state_after_other_fn
                .get_register(&register("callee_saved_reg"))
                .unwrap(),
            Data::Value(bv(13))
        );
        assert!(state_after_other_fn
            .get_register(&register("other_reg"))
            .unwrap()
            .is_top());
    }
}
