use super::*;
use crate::{
    analysis::{
        forward_interprocedural_fixpoint::Context as _, function_signature::context::Context,
    },
    bitvec, defs, expr, variable,
};

impl State {
    /// Generate a mock state for an ARM-32 state.
    pub fn mock_arm32() -> State {
        State::new(
            &Tid::new("mock_fn"),
            &variable!("sp:4"),
            &CallingConvention::mock_arm32(),
            2,
        )
    }

    /// Generate a mock state for an x64 state.
    pub fn mock_x64(tid_name: &str) -> State {
        State::new(
            &Tid::new(tid_name),
            &variable!("RSP:8"),
            &CallingConvention::mock_x64(),
            2,
        )
    }
}

/// Mock an abstract ID representing the stack.
fn mock_stack_id() -> AbstractIdentifier {
    AbstractIdentifier::from_var(Tid::new("mock_fn"), &variable!("sp:4"))
}

#[test]
fn test_new() {
    let state = State::mock_arm32();
    // Test the generated stack
    assert_eq!(&state.stack_id, &mock_stack_id());
    assert_eq!(state.stack.iter().len(), 0);
    // Assert that the register values are as expected
    assert_eq!(state.register.len(), 7); // 6 parameter register plus stack pointer
    assert_eq!(
        state.get_register(&variable!("sp:4")),
        DataDomain::from_target(mock_stack_id(), bitvec!("0x0:4").into())
    );
    // Check the generated tracked IDs
    assert_eq!(state.tracked_ids.len(), 6);
    for (id, access_pattern) in state.tracked_ids.iter() {
        assert_eq!(
            state.get_register(id.unwrap_register()),
            DataDomain::from_target(
                id.clone(),
                bitvec!(format!("0:{}", id.unwrap_register().size)).into()
            )
        );
        assert_eq!(access_pattern, &AccessPattern::new());
    }
}

#[test]
fn test_eval() {
    let mut state = State::mock_arm32();
    // Test the eval method
    let expr = expr!("sp:4 + 42:4");
    assert_eq!(
        state.eval(&expr),
        DataDomain::from_target(mock_stack_id(), bitvec!("42:4").into())
    );
    // Test the eval_parameter_arg method
    let arg = Arg::from_var(variable!("sp:4"), None);
    assert_eq!(
        state.eval_parameter_arg(&arg),
        DataDomain::from_target(mock_stack_id(), bitvec!("0x0:4").into())
    );
}

#[test]
fn test_extern_symbol_handling() {
    let mut state = State::mock_arm32();
    let extern_symbol = ExternSymbol::mock_arm32("mock_symbol");
    let cconv = CallingConvention::mock_arm32();
    let call_tid = Tid::new("call_tid");
    let param_id = AbstractIdentifier::from_var(Tid::new("mock_fn"), &variable!("r0:4"));
    let return_val_id = AbstractIdentifier::from_var(Tid::new("call_tid"), &variable!("r0:4"));
    // Test extern symbol handling.
    state.handle_generic_extern_symbol(
        &call_tid,
        &extern_symbol,
        &cconv,
        &RuntimeMemoryImage::mock(),
    );
    assert_eq!(
        state
            .tracked_ids
            .get(&param_id)
            .unwrap()
            .is_mutably_dereferenced(),
        true
    );
    let return_val = state.get_register(&variable!("r0:4"));
    assert_eq!(return_val.get_relative_values().iter().len(), 2);
    assert_eq!(
        return_val.get_relative_values().get(&param_id).unwrap(),
        &BitvectorDomain::new_top(ByteSize::new(4))
    );
    assert_eq!(
        return_val.get_relative_values().get(&param_id).unwrap(),
        &BitvectorDomain::new_top(ByteSize::new(4))
    );
    assert_eq!(
        return_val
            .get_relative_values()
            .get(&return_val_id)
            .unwrap(),
        &bitvec!("0:4").into()
    );
}

#[test]
fn test_substitute_global_mem_address() {
    let mut state = State::mock_arm32();
    let global_memory = RuntimeMemoryImage::mock();

    // Test that addresses into non-writeable memory do not get substituted.
    let global_address: DataDomain<BitvectorDomain> = bitvec!("0x1000:4").into();
    let substituted_address =
        state.substitute_global_mem_address(global_address.clone(), &global_memory);
    assert_eq!(global_address, substituted_address);
    // Test substitution for addresses into writeable global memory.
    let global_address: DataDomain<BitvectorDomain> = bitvec!("0x2000:4").into();
    let substituted_address = state.substitute_global_mem_address(global_address, &global_memory);
    let expected_global_id = AbstractIdentifier::from_global_address(
        state.get_current_function_tid(),
        &bitvec!("0x2000:4"),
    );
    assert_eq!(
        state.tracked_ids.get(&expected_global_id),
        Some(&AccessPattern::new())
    );
    assert_eq!(
        substituted_address,
        DataDomain::from_target(expected_global_id, bitvec!("0x0:4").into())
    );
}

#[test]
fn test_pointer_recursion_depth_limit_handling() {
    let project = Project::mock_arm32();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);
    let context = Context::new(&project, &graph);
    // Test interaction of gradually increasing the pointer recursion depth limit with a loop that
    // - iterates over an array
    // - recursively dereferences a variable
    let mut state = State::mock_arm32();
    let defs = defs![
        "instr_1: Store at r1:4 := r0:4",
        "instr_2: r1:4 = r1:4 + 0x1:4",
        "instr_3: r3:4 := Load from r3:4"
    ];
    let array_elem_location = AbstractLocation::mock("r1:4", &[0], 4);
    let array_elem_id = AbstractIdentifier::new(
        state.get_current_function_tid().clone(),
        array_elem_location,
    );
    let recursive_elem_location = AbstractLocation::mock("r3:4", &[0], 4);
    let recursive_elem_id = AbstractIdentifier::new(
        state.get_current_function_tid().clone(),
        recursive_elem_location,
    );
    // Iteration with depth limit 0
    state.pointer_recursion_depth_limit = 0;
    let prev_state = state.clone();
    for def in &defs {
        state = context.update_def(&state, def).unwrap();
    }
    state = state.merge(&prev_state);
    // No array element ID should have been created.
    assert!(state.tracked_ids.get(&array_elem_id).is_none());
    // No recursive access ID should have been created.
    assert!(state.tracked_ids.get(&recursive_elem_id).is_none());

    // Iteration with depth limit 1
    state.pointer_recursion_depth_limit = 1;
    let prev_state = state.clone();
    for def in &defs {
        state = context.update_def(&state, def).unwrap();
    }
    state = state.merge(&prev_state);
    // No array element ID should have been created.
    assert!(state.tracked_ids.get(&array_elem_id).is_none());
    // But the recursive access ID should now exist.
    assert!(state.tracked_ids.get(&recursive_elem_id).is_some());
}
