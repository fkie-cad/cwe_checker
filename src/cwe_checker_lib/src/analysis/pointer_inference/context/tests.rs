use super::super::ValueDomain;
use super::*;
use crate::{bitvec, def, expr, variable};

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(bitvec!(format!("{value}:8")))
}

fn new_id(time: &str, reg_name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(time),
        AbstractLocation::Register(variable!(format!("{reg_name}:8"))),
    )
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
    let project = Project::mock_x64();
    (
        project,
        Config {
            allocation_symbols: vec!["malloc".into()],
        },
    )
}

/// Create a mock context for unit tests.
/// Note that the function leaks memory!
fn mock_context() -> Context<'static> {
    let (project, config) = mock_project();
    let project = Box::new(project);
    let project = Box::leak(project);
    let analysis_results = Box::new(AnalysisResults::mock_from_project(project));
    let analysis_results = Box::leak(analysis_results);
    let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
    let mut mock_context = Context::new(analysis_results, config, log_sender);
    // Create mocked function signatures
    let fn_sigs = BTreeMap::from_iter([
        (Tid::new("caller"), FunctionSignature::mock_x64()),
        (Tid::new("callee"), FunctionSignature::mock_x64()),
    ]);
    let fn_sigs = Box::new(fn_sigs);
    let fn_sigs = Box::leak(fn_sigs);
    mock_context.fn_signatures = fn_sigs;

    mock_context
}

#[test]
fn context_problem_implementation() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    use crate::analysis::pointer_inference::Data;

    let context = mock_context();
    let mut state = State::new(&variable!("RSP:8"), Tid::new("main"), BTreeSet::new());

    let def = def!["def: RSP:8 = RSP:8 + -16:8"];
    let store_term = def!["Store at RSP:8 := 43:8"];

    // test update_def
    state = context.update_def(&state, &def).unwrap();
    let stack_pointer = Data::from_target(new_id("main", "RSP"), bv(-16));
    assert_eq!(state.eval(&expr!("RSP:8")), stack_pointer);
    state = context.update_def(&state, &store_term).unwrap();

    // Test extern function handling
    state.set_register(&variable!("RBP:8"), bv(13).into());
    state.set_register(&variable!("RSI:8"), bv(14).into());

    let malloc = call_term("malloc");
    let mut state_after_malloc = context.update_call_stub(&state, &malloc).unwrap();
    assert_eq!(
        state_after_malloc.get_register(&variable!("RAX:8")),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0))
    );
    assert_eq!(state_after_malloc.memory.get_num_objects(), 3);
    assert_eq!(
        state_after_malloc.get_register(&variable!("RSP:8")),
        state
            .get_register(&variable!("RSP:8"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_malloc.get_register(&variable!("RBP:8")),
        bv(13).into()
    );
    assert!(state_after_malloc
        .get_register(&variable!("RSI:8"))
        .is_top());

    state_after_malloc.set_register(
        &variable!("RBP:8"),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0)),
    );
    let free = call_term("free");
    let state_after_free = context
        .update_call_stub(&state_after_malloc, &free)
        .unwrap();
    assert!(state_after_free.get_register(&variable!("RDX:8")).is_top());
    assert_eq!(state_after_free.memory.get_num_objects(), 3);
    assert_eq!(
        state_after_free.get_register(&variable!("RBP:8")),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0))
    );

    let other_extern_fn = call_term("other_function");
    let state_after_other_fn = context.update_call_stub(&state, &other_extern_fn).unwrap();

    assert_eq!(
        state_after_other_fn.get_register(&variable!("RSP:8")),
        state
            .get_register(&variable!("RSP:8"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_other_fn.get_register(&variable!("RBP:8")),
        bv(13).into()
    );
    assert!(state_after_other_fn
        .get_register(&variable!("RSI:8"))
        .is_top());
}

#[test]
fn update_return() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    use crate::analysis::pointer_inference::object::ObjectType;
    use crate::analysis::pointer_inference::Data;
    let context = mock_context();
    let callee_tid = Tid::new("callee");
    let state_before_return = State::from_fn_sig(
        context.fn_signatures.get(&callee_tid).unwrap(),
        &variable!("RSP:8"),
        callee_tid.clone(),
    );
    let mut state_before_return = context
        .update_def(
            &state_before_return,
            &def!["stack_offset_on_return_adjustment: RSP:8 = RSP:8 + 8:8"],
        )
        .unwrap();

    let callee_created_heap_id = new_id("callee_created_heap", "RAX");
    state_before_return.memory.add_abstract_object(
        callee_created_heap_id.clone(),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    state_before_return.set_register(
        &variable!("RAX:8"),
        Data::from_target(callee_created_heap_id.clone(), bv(16)),
    );
    state_before_return.set_register(
        &variable!("RDX:8"),
        Data::from_target(new_id("callee", "RDI"), bv(0)),
    );

    let state_before_call = State::new(&variable!("RSP:8"), Tid::new("caller"), BTreeSet::new());
    let mut state_before_call = context
        .update_def(
            &state_before_call,
            &def!["stack_offset_on_call_adjustment: RSP:8 = RSP:8 + -16:8"],
        )
        .unwrap();
    let param_obj_id = new_id("caller_created_heap", "RAX");
    state_before_call.memory.add_abstract_object(
        param_obj_id.clone(),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    state_before_call.set_register(
        &variable!("RDI:8"),
        Data::from_target(param_obj_id.clone(), bv(0).into()),
    );
    state_before_call.set_register(
        &variable!("RBX:8"),
        Data::from_target(param_obj_id.clone(), bv(0).into()),
    );

    let state = context
        .update_return(
            Some(&state_before_return),
            Some(&state_before_call),
            &call_term("callee"),
            &return_term("return_target"),
            &None,
        )
        .unwrap();

    assert_eq!(state.stack_id, new_id("caller", "RSP"));
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        Data::from_target(
            callee_created_heap_id
                .with_path_hint(Tid::new("call_callee"))
                .unwrap(),
            bv(16).into()
        )
    );
    assert_eq!(
        state.get_register(&variable!("RBX:8")),
        Data::from_target(param_obj_id.clone(), bv(0).into())
    );
    assert_eq!(
        state.get_register(&variable!("RDX:8")),
        Data::from_target(param_obj_id.clone(), bv(0).into())
    );
    assert_eq!(
        state.get_register(&variable!("RSP:8")),
        Data::from_target(new_id("caller", "RSP"), bv(-8).into())
    );
    assert_eq!(state.memory.get_all_object_ids().len(), 4);
    assert!(state
        .memory
        .get_all_object_ids()
        .get(&param_obj_id)
        .is_some());
    assert!(state
        .memory
        .get_all_object_ids()
        .get(
            &callee_created_heap_id
                .with_path_hint(Tid::new("call_callee"))
                .unwrap()
        )
        .is_some());
}

#[test]
fn specialize_conditional() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    let (project, config) = mock_project();
    let (log_sender, _log_receiver) = crossbeam_channel::unbounded();
    let analysis_results = AnalysisResults::mock_from_project(&project);
    let context = Context::new(&analysis_results, config, log_sender);

    let mut state = State::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new());
    state.set_register(&variable!("RAX:8"), IntervalDomain::mock(-10, 20).into());

    let condition = Expression::BinOp {
        lhs: Box::new(expr!("RAX:8")),
        op: BinOpType::IntSLessEqual,
        rhs: Box::new(expr!("0:8")),
    };
    let block = Blk::mock();

    let result = context
        .specialize_conditional(&state, &condition, &block, false)
        .unwrap();
    assert_eq!(
        result.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(1, 20).into()
    );

    state.set_register(&variable!("RAX:8"), IntervalDomain::mock(0, 20).into());
    let result = context
        .specialize_conditional(&state, &condition, &block, true)
        .unwrap();
    assert_eq!(
        result.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 0, 0, None).into()
    );

    state.set_register(&variable!("RAX:8"), IntervalDomain::mock(-20, 0).into());
    let result = context.specialize_conditional(&state, &condition, &block, false);
    assert!(result.is_none());
}

#[test]
fn get_unsound_caller_ids() {
    let context = mock_context();
    let mut callee_id_to_caller_data_map = BTreeMap::new();
    callee_id_to_caller_data_map.insert(
        new_id("callee", "RDI"),
        Data::from_target(new_id("caller", "RAX"), bv(1).into()),
    );
    callee_id_to_caller_data_map.insert(
        new_id("callee", "RSI"),
        Data::from_target(new_id("caller", "RAX"), bv(2).into()),
    );

    let callee_tid = Tid::new("callee");
    let callee_state = State::from_fn_sig(
        context.fn_signatures.get(&callee_tid).unwrap(),
        &variable!("RSP:8"),
        callee_tid.clone(),
    );
    let callee_id_to_access_pattern_map = context.create_id_to_access_pattern_map(&callee_state);

    let unsound_ids = context.get_unsound_caller_ids(
        &callee_id_to_caller_data_map,
        &callee_id_to_access_pattern_map,
    );
    assert_eq!(unsound_ids, BTreeSet::from_iter([new_id("caller", "RAX")]));
}

#[test]
fn handle_extern_symbol_stubs() {
    let context = mock_context();
    let mut state = State::new(
        &context.project.stack_pointer_register,
        Tid::new("main"),
        BTreeSet::new(),
    );
    let mut extern_symbol = ExternSymbol::mock_x64("strchr");
    extern_symbol.parameters = vec![Arg::mock_register("RDI", 8), Arg::mock_register("RSI", 8)];

    state.set_register(
        &variable!("RDI:8"),
        Data::from_target(
            AbstractIdentifier::mock("param", "RBX", 8),
            bitvec!("0:8").into(),
        ),
    );
    let mut new_state = state.clone();
    let cconv = CallingConvention::mock_x64();
    new_state.clear_non_callee_saved_register(&cconv.callee_saved_register[..]);

    context.handle_parameter_access_for_stubbed_functions(&state, &mut new_state, &extern_symbol);
    let return_value = context.compute_return_value_for_stubbed_function(&state, &extern_symbol);
    new_state.set_register(&cconv.integer_return_register[0], return_value);

    assert_eq!(
        new_state.get_register(&variable!("RAX:8")),
        Data::from_target(
            AbstractIdentifier::mock("param", "RBX", 8),
            IntervalDomain::new_top(ByteSize::new(8)),
        )
        .merge(&bitvec!("0:8").into())
    );
}

#[test]
fn test_merge_global_mem_from_callee() {
    let context = mock_context();
    let mut caller_state = State::new(
        &context.project.stack_pointer_register,
        Tid::new("caller"),
        BTreeSet::from([0x2000, 0x2002, 0x3000]),
    );
    let mut callee_state = State::new(
        &context.project.stack_pointer_register,
        Tid::new("callee"),
        BTreeSet::from([0x2000, 0x2002]),
    );
    let write = |state: &mut State, address: u64, value: u16| {
        state
            .write_to_address(
                &expr!(format!("{address}:8")),
                &Data::from(bitvec!(format!("{value}:2"))),
                &context.project.runtime_memory_image,
            )
            .unwrap();
    };
    let load = |state: &State, address: u64| -> Data {
        state
            .load_value(
                &expr!(format!("{address}:8")),
                ByteSize::new(2),
                &context.project.runtime_memory_image,
            )
            .unwrap()
    };
    write(&mut caller_state, 0x2000, 0);
    write(&mut caller_state, 0x2002, 2);
    write(&mut caller_state, 0x3000, 4);
    write(&mut callee_state, 0x2000, 42);

    let callee_global_mem = callee_state
        .memory
        .get_object(&callee_state.get_global_mem_id())
        .unwrap();
    let callee_fn_sig = FunctionSignature::mock_x64();
    let replacement_map = BTreeMap::from([(
        callee_state.get_global_mem_id(),
        Data::from_target(caller_state.get_global_mem_id(), bitvec!("0:8").into()),
    )]);

    context.merge_global_mem_from_callee(
        &mut caller_state,
        callee_global_mem,
        &replacement_map,
        &callee_fn_sig,
        &Tid::new("call"),
    );

    assert_eq!(load(&caller_state, 0x2000), bitvec!("42:2").into());
    let mut expected_result = Data::from(bitvec!("2:2"));
    expected_result.set_contains_top_flag();
    assert_eq!(load(&caller_state, 0x2002), expected_result);
    assert_eq!(load(&caller_state, 0x3000), bitvec!("4:2").into());
}
