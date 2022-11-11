use super::*;
use std::collections::HashSet;

#[test]
fn test_compute_return_values_of_call() {
    let project = Project::mock_x64();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());

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
        AbstractIdentifier::from_var(Tid::new("call_tid"), &Variable::mock("RAX", 8)),
        Bitvector::from_i64(0).into(),
    );
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&Variable::mock("RAX", 8), expected_val));
    // Test returning a known value.
    let param_ref = DataDomain::from_target(
        AbstractIdentifier::from_var(Tid::new("callee"), &Variable::mock("RDI", 8)),
        Bitvector::from_i64(0).into(),
    );
    callee_state.set_register(&Variable::mock("RAX", 8), param_ref);
    let expected_val = DataDomain::from_target(
        AbstractIdentifier::from_var(Tid::new("caller"), &Variable::mock("RDI", 8)),
        Bitvector::from_i64(0).into(),
    );
    let return_values = context.compute_return_values_of_call(
        &mut caller_state,
        &callee_state,
        project.get_standard_calling_convention().unwrap(),
        &call,
    );
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&Variable::mock("RAX", 8), expected_val));
}

#[test]
fn test_call_stub_handling() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());

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
            Arg::from_var(Variable::mock("r0", 4), None),
            AccessPattern::new().with_read_flag()
        )]
    );
    assert_eq!(
        state.get_register(&Variable::mock("r0", 4)),
        DataDomain::from_target(
            AbstractIdentifier::mock(call_tid, "r0", 4),
            Bitvector::from_i32(0).into()
        )
        .merge(&Bitvector::zero(ByteSize::new(4).into()).into())
    );

    // Test handling of sprintf call
    let mut state = State::new(
        &Tid::new("func"),
        &project.stack_pointer_register,
        project.get_standard_calling_convention().unwrap(),
    );
    // Set the format string param register to a pointer to the string 'cat %s %s %s %s'.
    state.set_register(&Variable::mock("r1", 4), Bitvector::from_i32(0x6000).into());
    let extern_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let call_tid = Tid::new("call_sprintf");
    context.handle_extern_symbol_call(&mut state, &extern_symbol, &call_tid);
    let params = state.get_params_of_current_function();
    assert_eq!(
        params[0],
        (
            Arg::from_var(Variable::mock("r0", 4), None),
            AccessPattern::new_unknown_access()
        )
    );
    assert_eq!(
        params[1],
        (
            Arg::from_var(Variable::mock("r2", 4), None),
            AccessPattern::new()
                .with_read_flag()
                .with_dereference_flag()
        )
    );
    assert_eq!(params.len(), 5);
}

#[test]
fn test_get_global_mem_address() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());

    let context = Context::new(&project, &graph);
    // Check global address from abstract ID
    let global_address_id: DataDomain<BitvectorDomain> = DataDomain::from_target(
        AbstractIdentifier::from_global_address(&Tid::new("fn_tid"), &Bitvector::from_i32(0x2000)),
        Bitvector::from_i32(0x2).into(),
    );
    let result = context.get_global_mem_address(&global_address_id);
    assert_eq!(result, Some(Bitvector::from_i32(0x2002)));
    // Check global address from absolute value
    let global_address_const = Bitvector::from_i32(0x2003).into();
    let result = context.get_global_mem_address(&global_address_const);
    assert_eq!(result, Some(Bitvector::from_i32(0x2003)));
    // Check global address not returned if it may not be unique
    let value = global_address_id.merge(&global_address_const);
    let result = context.get_global_mem_address(&value);
    assert!(result.is_none());
}
