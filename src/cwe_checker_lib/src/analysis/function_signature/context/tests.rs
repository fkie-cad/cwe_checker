use super::*;
use crate::{analysis::forward_interprocedural_fixpoint::Context as _, bitvec, def, variable};

#[test]
fn test_compute_return_values_of_call() {
    let project = Project::mock_x64();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);

    let context = Context::new(&project, &graph);

    let mut caller_state = State::mock_x64("caller");
    let mut callee_state = State::mock_x64("callee");
    let call = Term {
        tid: Tid::new("call_tid"),
        term: Jmp::Call {
            target: Tid::new("callee"),
            return_: Some(Tid::new("return_tid")),
        },
    };
    // Test returning a value of unknown origin (since RAX does not contain a reference to the input register).
    let return_values = context.compute_return_values_of_call(
        &mut caller_state,
        &callee_state,
        project.get_standard_calling_convention().unwrap(),
        &call,
    );
    let expected_val = DataDomain::from_target(
        AbstractIdentifier::mock("call_tid", "RAX", 8),
        bitvec!("0x0:8").into(),
    );
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&variable!("RAX:8"), expected_val));
    // Test returning a known value.
    let param_ref = DataDomain::from_target(
        AbstractIdentifier::mock("callee", "RDI", 8),
        bitvec!("0x0:8").into(),
    );
    callee_state.set_register(&variable!("RAX:8"), param_ref);
    let expected_val = DataDomain::mock_from_target_map(BTreeMap::from([
        (
            AbstractIdentifier::mock("caller", "RDI", 8),
            bitvec!("0x0:8").into(),
        ),
        (
            AbstractIdentifier::mock("call_tid", "RAX", 8),
            bitvec!("0x0:8").into(),
        ),
    ]));
    let return_values = context.compute_return_values_of_call(
        &mut caller_state,
        &callee_state,
        project.get_standard_calling_convention().unwrap(),
        &call,
    );
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&variable!("RAX:8"), expected_val));
}

#[test]
fn test_call_stub_handling() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);

    let context = Context::new(&project, &graph);

    // Test handling of malloc call
    let mut state = State::new(
        &Tid::new("func"),
        &project.stack_pointer_register,
        project.get_standard_calling_convention().unwrap(),
    );
    let extern_symbol = ExternSymbol::mock_malloc_symbol_arm();
    let call_tid = Tid::new("call_malloc");
    context.handle_extern_symbol_call(&mut state, &extern_symbol, &call_tid);
    assert_eq!(
        state.get_params_of_current_function(),
        vec![(
            &AbstractLocation::from_var(&variable!("r0:4")).unwrap(),
            AccessPattern::new().with_read_flag()
        )]
    );
    assert_eq!(
        state.get_register(&variable!("r0:4")),
        DataDomain::from_target(
            AbstractIdentifier::mock(call_tid, "r0", 4),
            bitvec!("0x0:4").into()
        )
        .merge(&bitvec!("0x0:4").into())
    );

    // Test handling of sprintf call
    let mut state = State::new(
        &Tid::new("func"),
        &project.stack_pointer_register,
        project.get_standard_calling_convention().unwrap(),
    );
    // Set the format string param register to a pointer to the string 'cat %s %s %s %s'.
    state.set_register(&variable!("r1:4"), bitvec!("0x6000:4").into());
    let extern_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let call_tid = Tid::new("call_sprintf");
    context.handle_extern_symbol_call(&mut state, &extern_symbol, &call_tid);
    let params = state.get_params_of_current_function();
    assert_eq!(
        params[0],
        (
            &AbstractLocation::from_var(&variable!("r0:4")).unwrap(),
            AccessPattern::new_unknown_access()
        )
    );
    assert_eq!(
        params[1],
        (
            &AbstractLocation::from_var(&variable!("r2:4")).unwrap(),
            AccessPattern::new()
                .with_read_flag()
                .with_dereference_flag()
        )
    );
    assert_eq!(params.len(), 5);
}

#[test]
fn test_stack_register_adjustment_after_call() {
    let project = Project::mock_x64();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);
    let context = Context::new(&project, &graph);
    let mut state_before_call = State::mock_x64("mock_fn");
    let stack_id = AbstractIdentifier::mock("mock_fn", "RSP", 8);
    state_before_call.set_register(
        &variable!("RSP:8"),
        DataDomain::from_target(stack_id.clone(), bitvec!("0x-20:8").into()),
    );
    let call_term = Term {
        tid: Tid::new("call_tid"),
        term: Jmp::CallInd {
            target: Expression::Var(variable!("R15:8")),
            return_: Some(Tid::new("return_")),
        },
    };
    // Test adjustment on extern calls
    let state_after_call = context
        .update_call_stub(&state_before_call, &call_term)
        .unwrap();
    let adjusted_sp = state_after_call.get_register(&variable!("RSP:8"));
    assert_eq!(
        adjusted_sp,
        DataDomain::from_target(stack_id.clone(), bitvec!("0x-18:8").into())
    );
    // Test adjustment on intern calls
    let state_before_return = State::mock_x64("callee");
    let state_after_call = context
        .update_return(
            Some(&state_before_return),
            Some(&state_before_call),
            &call_term,
            &call_term,
            &None,
        )
        .unwrap();
    let adjusted_sp = state_after_call.get_register(&variable!("RSP:8"));
    assert_eq!(
        adjusted_sp,
        DataDomain::from_target(stack_id.clone(), bitvec!("0x-18:8").into())
    );
}

#[test]
fn test_get_global_mem_address() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);

    let context = Context::new(&project, &graph);
    // Check global address from abstract ID
    let global_address_id: DataDomain<BitvectorDomain> = DataDomain::from_target(
        AbstractIdentifier::from_global_address(&Tid::new("fn_tid"), &bitvec!("0x2000:4")),
        bitvec!("0x2:4").into(),
    );
    let result = context.get_global_mem_address(&global_address_id);
    assert_eq!(result, Some(bitvec!("0x2002:4")));
    // Check global address from absolute value
    let global_address_const = bitvec!("0x2003:4").into();
    let result = context.get_global_mem_address(&global_address_const);
    assert_eq!(result, Some(bitvec!("0x2003:4")));
    // Check global address not returned if it may not be unique
    let value = global_address_id.merge(&global_address_const);
    let result = context.get_global_mem_address(&value);
    assert!(result.is_none());
}

#[test]
fn test_generation_of_nested_ids_and_access_patterns_on_load_and_store() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);
    let context = Context::new(&project, &graph);
    let state = State::mock_arm32();
    // Load from a tracked pointer value
    let def = def!["load_instr: r0:4 := Load from r1:4 + 0x10:4"];
    let new_state = context.update_def(&state, &def).unwrap();
    let loaded_value = new_state.get_register(&variable!("r0:4"));
    assert_eq!(
        loaded_value,
        DataDomain::from_target(
            AbstractIdentifier::new(
                Tid::new("mock_fn"),
                AbstractLocation::mock("r1:4", &[16], 4)
            ),
            bitvec!("0x0:4").into()
        )
    );
    let params = new_state.get_params_of_current_function();
    assert_eq!(params.len(), 1);
    assert!(params.contains(&(
        &AbstractLocation::mock("r1:4", &[], 4),
        AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag()
    )));
    // Load from an untracked register value
    let def = def!["load_instr: r0:4 := Load from r8:4 + 0x10:4"];
    let new_state = context.update_def(&state, &def).unwrap();
    let loaded_value = new_state.get_register(&variable!("r0:4"));
    assert!(loaded_value.is_top());
    assert_eq!(new_state.get_params_of_current_function(), []);
    // Store a tracked pointer value
    let def = def!["store_instr: Store at r0:4 := r1:4 + 0x10:4"];
    let new_state = context.update_def(&state, &def).unwrap();
    let params = new_state.get_params_of_current_function();
    assert_eq!(params.len(), 2);
    assert!(params.contains(&(
        &AbstractLocation::mock("r0:4", &[], 4),
        AccessPattern::new()
            .with_read_flag()
            .with_mutably_dereferenced_flag()
    )));
    assert!(params.contains(&(
        &AbstractLocation::mock("r1:4", &[], 4),
        AccessPattern::new().with_read_flag()
    )));
    // Store to an untracked register value
    let def = def!["store_instr: Store at r8:4 := r1:4 + 0x10:4"];
    let new_state = context.update_def(&state, &def).unwrap();
    let params = new_state.get_params_of_current_function();
    assert_eq!(params.len(), 1);
    assert!(params.contains(&(
        &AbstractLocation::mock("r1:4", &[], 4),
        AccessPattern::new().with_read_flag()
    )));
}
