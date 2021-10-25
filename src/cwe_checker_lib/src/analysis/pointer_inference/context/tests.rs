use crate::intermediate_representation::DatatypeProperties;

use super::*;
use std::{collections::HashSet, iter::FromIterator};

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(time: &str, reg_name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(time),
        AbstractLocation::Register(Variable::mock(reg_name, ByteSize::new(8))),
    )
}

fn mock_extern_symbol(name: &str) -> (Tid, ExternSymbol) {
    let arg = Arg::Register {
        var: register("RDX"),
        data_type: None,
    };
    let tid = Tid::new("extern_".to_string() + name);
    (
        tid.clone(),
        ExternSymbol {
            tid,
            addresses: vec![],
            name: name.into(),
            calling_convention: None,
            parameters: vec![arg.clone()],
            return_values: vec![arg],
            no_return: false,
            has_var_args: false,
        },
    )
}

fn register(name: &str) -> Variable {
    Variable {
        name: name.into(),
        size: ByteSize::new(8),
        is_temp: false,
    }
}

fn reg_add_term(name: &str, value: i64, tid_name: &str) -> Term<Def> {
    let add_expr = Expression::Var(register(name)).plus_const(value);
    Term {
        tid: Tid::new(format!("{}", tid_name)),
        term: Def::Assign {
            var: register(name),
            value: add_expr,
        },
    }
}

fn call_term(target_name: &str) -> Term<Jmp> {
    Term {
        tid: Tid::new(format!("call_{}", target_name)),
        term: Jmp::Call {
            target: Tid::new(target_name),
            return_: None,
        },
    }
}

fn return_term(target_name: &str) -> Term<Jmp> {
    Term {
        tid: Tid::new(format!("return")),
        term: Jmp::Return(Expression::Unknown {
            description: target_name.into(),
            size: ByteSize::new(8),
        }),
    }
}

fn mock_project() -> (Project, Config) {
    let program = Program {
        subs: BTreeMap::new(),
        extern_symbols: vec![
            mock_extern_symbol("malloc"),
            mock_extern_symbol("free"),
            mock_extern_symbol("other"),
        ]
        .into_iter()
        .collect(),
        entry_points: Vec::new(),
        address_base_offset: 0,
    };
    let program_term = Term {
        tid: Tid::new("program"),
        term: program,
    };
    let cconv = CallingConvention {
        name: "__cdecl".to_string(),
        integer_parameter_register: vec!["RDX".to_string()],
        float_parameter_register: vec!["XMM0".to_string()],
        return_register: vec!["RDX".to_string()],
        callee_saved_register: vec!["callee_saved_reg".to_string()],
    };
    let register_list = vec!["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
        .into_iter()
        .map(|name| Variable::mock(name, ByteSize::new(8)))
        .collect();
    (
        Project {
            program: program_term,
            cpu_architecture: "x86_64".to_string(),
            stack_pointer_register: register("RSP"),
            calling_conventions: BTreeMap::from_iter([(cconv.name.clone(), cconv)]),
            register_list,
            datatype_properties: DatatypeProperties::mock(),
        },
        Config {
            allocation_symbols: vec!["malloc".into()],
            deallocation_symbols: vec!["free".into()],
        },
    )
}

#[test]
fn context_problem_implementation() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    use crate::analysis::pointer_inference::Data;
    use Expression::*;

    let (project, config) = mock_project();
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
    let context = Context::new(&project, &runtime_memory_image, &graph, config, log_sender);
    let mut state = State::new(&register("RSP"), Tid::new("main"));

    let def = Term {
        tid: Tid::new("def"),
        term: Def::Assign {
            var: register("RSP"),
            value: Var(register("RSP")).plus_const(-16),
        },
    };
    let store_term = Term {
        tid: Tid::new("store"),
        term: Def::Store {
            address: Var(register("RSP")),
            value: Const(Bitvector::from_i64(42)),
        },
    };

    // test update_def
    state = context.update_def(&state, &def).unwrap();
    let stack_pointer = Data::from_target(new_id("main", "RSP"), bv(-16));
    assert_eq!(state.eval(&Var(register("RSP"))), stack_pointer);
    state = context.update_def(&state, &store_term).unwrap();

    // Test update_call
    let target_block = Term {
        tid: Tid::new("func_start"),
        term: Blk {
            defs: Vec::new(),
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    let sub = Term {
        tid: Tid::new("caller_sub"),
        term: Sub {
            name: "caller_sub".into(),
            blocks: vec![target_block.clone()],
        },
    };
    let target_node = crate::analysis::graph::Node::BlkStart(&target_block, &sub);
    let call = call_term("func");
    let mut callee_state = context.update_call(&state, &call, &target_node).unwrap();
    assert_eq!(callee_state.stack_id, new_id("func", "RSP"));
    assert_eq!(callee_state.caller_stack_ids.len(), 1);
    assert_eq!(
        callee_state.caller_stack_ids.iter().next().unwrap(),
        &new_id("call_func", "RSP")
    );

    callee_state
        .memory
        .set_value(
            Data::from_target(new_id("func", "RSP"), bv(-30)),
            bv(33).into(),
        )
        .unwrap();
    // Emulate  removing the return pointer from the stack for x64
    let stack_pointer_update_def = Term {
        tid: Tid::new("stack_pointer_update_def"),
        term: Def::Assign {
            var: register("RSP"),
            value: BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Var(register("RSP"))),
                rhs: Box::new(Const(Bitvector::from_i64(8))),
            },
        },
    };
    callee_state = context
        .update_def(&callee_state, &stack_pointer_update_def)
        .unwrap();
    // Test update_return
    let return_state = context
        .update_return(
            Some(&callee_state),
            Some(&state),
            &call,
            &return_term("return_target"),
        )
        .unwrap();
    assert_eq!(return_state.stack_id, new_id("main", "RSP"));
    assert_eq!(return_state.caller_stack_ids, BTreeSet::new());
    assert_eq!(return_state.memory, state.memory);
    assert_eq!(
        return_state.get_register(&register("RSP")),
        state
            .get_register(&register("RSP"))
            .bin_op(BinOpType::IntAdd, &Bitvector::from_i64(8).into())
    );

    state.set_register(&register("callee_saved_reg"), bv(13).into());
    state.set_register(&register("other_reg"), bv(14).into());

    let malloc = call_term("extern_malloc");
    let mut state_after_malloc = context.update_call_stub(&state, &malloc).unwrap();
    assert_eq!(
        state_after_malloc.get_register(&register("RDX")),
        Data::from_target(new_id("call_extern_malloc", "RDX"), bv(0))
    );
    assert_eq!(state_after_malloc.memory.get_num_objects(), 2);
    assert_eq!(
        state_after_malloc.get_register(&register("RSP")),
        state
            .get_register(&register("RSP"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_malloc.get_register(&register("callee_saved_reg")),
        bv(13).into()
    );
    assert!(state_after_malloc
        .get_register(&register("other_reg"))
        .is_top());

    state_after_malloc.set_register(
        &register("callee_saved_reg"),
        Data::from_target(new_id("call_extern_malloc", "RDX"), bv(0)),
    );
    let free = call_term("extern_free");
    let state_after_free = context
        .update_call_stub(&state_after_malloc, &free)
        .unwrap();
    assert!(state_after_free.get_register(&register("RDX")).is_top());
    assert_eq!(state_after_free.memory.get_num_objects(), 2);
    assert_eq!(
        state_after_free.get_register(&register("callee_saved_reg")),
        Data::from_target(new_id("call_extern_malloc", "RDX"), bv(0))
    );

    let other_extern_fn = call_term("extern_other");
    let state_after_other_fn = context.update_call_stub(&state, &other_extern_fn).unwrap();

    assert_eq!(
        state_after_other_fn.get_register(&register("RSP")),
        state
            .get_register(&register("RSP"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_other_fn.get_register(&register("callee_saved_reg")),
        bv(13).into()
    );
    assert!(state_after_other_fn
        .get_register(&register("other_reg"))
        .is_top());
}

#[test]
fn update_return() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    use crate::analysis::pointer_inference::object::ObjectType;
    use crate::analysis::pointer_inference::Data;
    let (project, config) = mock_project();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
    let context = Context::new(&project, &runtime_memory_image, &graph, config, log_sender);
    let state_before_return = State::new(&register("RSP"), Tid::new("callee"));
    let mut state_before_return = context
        .update_def(
            &state_before_return,
            &reg_add_term("RSP", 8, "stack_offset_on_return_adjustment"),
        )
        .unwrap();

    let callsite_id = new_id("call_callee", "RSP");
    state_before_return.memory.add_abstract_object(
        callsite_id.clone(),
        bv(0).into(),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state_before_return
        .caller_stack_ids
        .insert(callsite_id.clone());
    state_before_return
        .ids_known_to_caller
        .insert(callsite_id.clone());

    let other_callsite_id = new_id("call_callee_other", "RSP");
    state_before_return.memory.add_abstract_object(
        other_callsite_id.clone(),
        bv(0).into(),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state_before_return
        .caller_stack_ids
        .insert(other_callsite_id.clone());
    state_before_return
        .ids_known_to_caller
        .insert(other_callsite_id.clone());
    state_before_return.set_register(
        &register("RDX"),
        Data::from_target(new_id("call_callee_other", "RSP"), bv(-32)),
    );

    let state_before_call = State::new(&register("RSP"), Tid::new("original_caller_id"));
    let mut state_before_call = context
        .update_def(
            &state_before_call,
            &reg_add_term("RSP", -16, "stack_offset_on_call_adjustment"),
        )
        .unwrap();
    let caller_caller_id = new_id("caller_caller", "RSP");
    state_before_call.memory.add_abstract_object(
        caller_caller_id.clone(),
        bv(0).into(),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state_before_call
        .caller_stack_ids
        .insert(caller_caller_id.clone());
    state_before_call
        .ids_known_to_caller
        .insert(caller_caller_id.clone());

    let state = context
        .update_return(
            Some(&state_before_return),
            Some(&state_before_call),
            &call_term("callee"),
            &return_term("return_target"),
        )
        .unwrap();

    let mut caller_caller_set = BTreeSet::new();
    caller_caller_set.insert(caller_caller_id);
    assert_eq!(state.ids_known_to_caller, caller_caller_set.clone());
    assert_eq!(state.caller_stack_ids, caller_caller_set.clone());
    assert_eq!(state.stack_id, new_id("original_caller_id", "RSP"));
    assert!(state_before_return.memory.get_all_object_ids().len() == 3);
    assert!(state.memory.get_all_object_ids().len() == 2);
    assert!(state
        .memory
        .get_all_object_ids()
        .get(&new_id("original_caller_id", "RSP"))
        .is_some());
    assert!(state
        .memory
        .get_all_object_ids()
        .get(&new_id("caller_caller", "RSP"))
        .is_some());
    let expected_rsp = Data::from_target(new_id("original_caller_id", "RSP"), bv(-8));
    assert_eq!(state.get_register(&register("RSP")), expected_rsp);
}

#[test]
fn specialize_conditional() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    let (project, config) = mock_project();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
    let context = Context::new(&project, &runtime_memory_image, &graph, config, log_sender);

    let mut state = State::new(&register("RSP"), Tid::new("func"));
    state.set_register(&register("RAX"), IntervalDomain::mock(-10, 20).into());

    let condition = Expression::BinOp {
        lhs: Box::new(Expression::Var(register("RAX"))),
        op: BinOpType::IntSLessEqual,
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(8).into()))),
    };
    let block = Blk::mock();

    let result = context
        .specialize_conditional(&state, &condition, &block, false)
        .unwrap();
    assert_eq!(
        result.get_register(&register("RAX")),
        IntervalDomain::mock(1, 20).into()
    );

    state.set_register(&register("RAX"), IntervalDomain::mock(0, 20).into());
    let result = context
        .specialize_conditional(&state, &condition, &block, true)
        .unwrap();
    assert_eq!(
        result.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 0, 0, None).into()
    );

    state.set_register(&register("RAX"), IntervalDomain::mock(-20, 0).into());
    let result = context.specialize_conditional(&state, &condition, &block, false);
    assert!(result.is_none());
}
