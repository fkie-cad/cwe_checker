use super::*;
use crate::intermediate_representation::DatatypeProperties;

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
    let arg = Arg::from_var(register("RDX"), None);
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
    let project = Project::mock_x64();
    (
        project,
        Config {
            allocation_symbols: vec!["malloc".into()],
            deallocation_symbols: vec!["free".into()],
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
    let fn_sigs = BTreeMap::from_iter([(Tid::new("callee"), FunctionSignature::mock_x64())]);
    let fn_sigs = Box::new(fn_sigs);
    let fn_sigs = Box::leak(fn_sigs);
    mock_context.fn_signatures = fn_sigs;

    mock_context
}

#[test]
fn context_problem_implementation() {
    use crate::analysis::forward_interprocedural_fixpoint::Context as IpFpContext;
    use crate::analysis::pointer_inference::Data;
    use Expression::*;

    let context = mock_context();
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

    // Test extern function handling
    state.set_register(&register("RBP"), bv(13).into());
    state.set_register(&register("RSI"), bv(14).into());

    let malloc = call_term("malloc");
    let mut state_after_malloc = context.update_call_stub(&state, &malloc).unwrap();
    assert_eq!(
        state_after_malloc.get_register(&register("RAX")),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0))
    );
    assert_eq!(state_after_malloc.memory.get_num_objects(), 2);
    assert_eq!(
        state_after_malloc.get_register(&register("RSP")),
        state
            .get_register(&register("RSP"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_malloc.get_register(&register("RBP")),
        bv(13).into()
    );
    assert!(state_after_malloc.get_register(&register("RSI")).is_top());

    state_after_malloc.set_register(
        &register("RBP"),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0)),
    );
    let free = call_term("free");
    let state_after_free = context
        .update_call_stub(&state_after_malloc, &free)
        .unwrap();
    assert!(state_after_free.get_register(&register("RDX")).is_top());
    assert_eq!(state_after_free.memory.get_num_objects(), 2);
    assert_eq!(
        state_after_free.get_register(&register("RBP")),
        Data::from_target(new_id("call_malloc", "RAX"), bv(0))
    );

    let other_extern_fn = call_term("other_function");
    let state_after_other_fn = context.update_call_stub(&state, &other_extern_fn).unwrap();

    assert_eq!(
        state_after_other_fn.get_register(&register("RSP")),
        state
            .get_register(&register("RSP"))
            .bin_op(BinOpType::IntAdd, &bv(8).into())
    );
    assert_eq!(
        state_after_other_fn.get_register(&register("RBP")),
        bv(13).into()
    );
    assert!(state_after_other_fn.get_register(&register("RSI")).is_top());
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
        &register("RSP"),
        callee_tid.clone(),
    );
    let mut state_before_return = context
        .update_def(
            &state_before_return,
            &reg_add_term("RSP", 8, "stack_offset_on_return_adjustment"),
        )
        .unwrap();

    let callee_created_heap_id = new_id("callee_created_heap", "RAX");
    state_before_return.memory.add_abstract_object(
        callee_created_heap_id.clone(),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    state_before_return.set_register(
        &register("RAX"),
        Data::from_target(callee_created_heap_id.clone(), bv(16)),
    );
    state_before_return.set_register(
        &register("RDX"),
        Data::from_target(new_id("callee", "RDI"), bv(0)),
    );

    let state_before_call = State::new(&register("RSP"), Tid::new("caller"));
    let mut state_before_call = context
        .update_def(
            &state_before_call,
            &reg_add_term("RSP", -16, "stack_offset_on_call_adjustment"),
        )
        .unwrap();
    let param_obj_id = new_id("caller_created_heap", "RAX");
    state_before_call.memory.add_abstract_object(
        param_obj_id.clone(),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    state_before_call.set_register(
        &register("RDI"),
        Data::from_target(param_obj_id.clone(), bv(0).into()),
    );
    state_before_call.set_register(
        &register("RBX"),
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
        state.get_register(&register("RAX")),
        Data::from_target(
            callee_created_heap_id
                .with_path_hint(Tid::new("call_callee"))
                .unwrap(),
            bv(16).into()
        )
    );
    assert_eq!(
        state.get_register(&register("RBX")),
        Data::from_target(param_obj_id.clone(), bv(0).into())
    );
    assert_eq!(
        state.get_register(&register("RDX")),
        Data::from_target(param_obj_id.clone(), bv(0).into())
    );
    assert_eq!(
        state.get_register(&register("RSP")),
        Data::from_target(new_id("caller", "RSP"), bv(-8).into())
    );
    assert!(state.memory.get_all_object_ids().len() == 3);
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
        &register("RSP"),
        callee_tid.clone(),
    );
    let callee_id_to_access_pattern_map = context.create_id_to_access_pattern_map(&callee_state);

    let unsound_ids = context.get_unsound_caller_ids(
        &callee_id_to_caller_data_map,
        &callee_id_to_access_pattern_map,
    );
    assert_eq!(unsound_ids, BTreeSet::from_iter([new_id("caller", "RAX")]));
}
