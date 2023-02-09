use std::collections::HashSet;

use crate::{
    abstract_domain::{
        AbstractIdentifier, AbstractLocation, CharacterInclusionDomain, DataDomain, IntervalDomain,
    },
    analysis::pointer_inference::PointerInference as PointerInferenceComputation,
    analysis::{
        forward_interprocedural_fixpoint::Context,
        string_abstraction::{context::symbol_calls::tests::Setup, tests::*},
    },
    bitvec, def,
    intermediate_representation::*,
    variable,
};

#[test]
fn test_update_def() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);
    setup.context.block_first_def_set = HashSet::new();

    let assign_def = def!["assign_def: r1:4 = 0x7000:4"];
    let load_def = Def::load_var_content_from_temp_var("load_def", "r5", "r2");
    let store_def = Def::store_var_content_at_temp_var("store_def", "r0", "r5");

    let new_state = setup
        .context
        .update_def(&setup.state_before_call, &assign_def)
        .unwrap();

    let absolute_target = DataDomain::from(bitvec!("0x7000:4"));

    assert_eq!(
        absolute_target,
        *new_state
            .get_variable_to_pointer_map()
            .get(&variable!("r1:4"))
            .unwrap()
    );

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );

    let loaded_pointer = DataDomain::from_target(stack_id.clone(), IntervalDomain::mock_i32(4, 4));
    let pointer_to_pointer =
        DataDomain::from_target(stack_id.clone(), IntervalDomain::mock_i32(8, 8));

    let _ = setup.pi_state_before_symbol_call.store_value(
        &pointer_to_pointer,
        &loaded_pointer,
        &project.runtime_memory_image,
    );

    let r2_reg = Variable {
        name: "r2".into(),
        size: ByteSize::new(4),
        is_temp: true,
    };

    setup
        .pi_state_before_symbol_call
        .set_register(&r2_reg, pointer_to_pointer);

    setup
        .state_before_call
        .set_pointer_inference_state(Some(setup.pi_state_before_symbol_call.clone()));

    setup
        .state_before_call
        .add_new_variable_to_pointer_entry(variable!("r3:4"), loaded_pointer.clone());

    let new_state = setup
        .context
        .update_def(&setup.state_before_call, &load_def)
        .unwrap();

    assert_eq!(
        loaded_pointer,
        *new_state
            .get_variable_to_pointer_map()
            .get(&variable!("r5:4"))
            .unwrap()
    );

    let store_target = DataDomain::from_target(stack_id, IntervalDomain::mock_i32(12, 12));

    let r0_reg = Variable {
        name: "r0".into(),
        size: ByteSize::new(4),
        is_temp: true,
    };

    setup
        .pi_state_before_symbol_call
        .set_register(&r0_reg, store_target);

    setup
        .pi_state_before_symbol_call
        .set_register(&variable!("r5:4"), absolute_target.clone());

    setup
        .state_before_call
        .set_pointer_inference_state(Some(setup.pi_state_before_symbol_call));

    let new_state = setup
        .context
        .update_def(&setup.state_before_call, &store_def)
        .unwrap();

    assert_eq!(
        absolute_target,
        *new_state
            .get_stack_offset_to_pointer_map()
            .get(&12)
            .unwrap()
    );
}

#[test]
fn test_update_jump() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .update_jump(
            &setup.state_before_call,
            &Jmp::branch("start1", "end1"),
            Some(&Jmp::branch("start2", "end2")),
            &Blk::mock(),
        )
        .unwrap();

    assert_eq!(None, new_state.get_pointer_inference_state());
}

#[test]
fn test_update_return() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let pointer = DataDomain::from(bitvec!("0x6000:4"));
    let callee_saved_reg = variable!("r11:4");
    let non_callee_saved_reg = variable!("r0:4");

    setup
        .state_before_call
        .add_new_variable_to_pointer_entry(callee_saved_reg.clone(), pointer.clone());

    setup
        .state_before_call
        .add_new_variable_to_pointer_entry(non_callee_saved_reg.clone(), pointer.clone());

    let new_state = setup.context.update_return(
        None,
        None,
        &Jmp::branch("start1", "end1"),
        &Jmp::branch("start2", "end2"),
        &None,
    );

    assert_eq!(None, new_state);

    let new_state = setup
        .context
        .update_return(
            Some(&setup.state_before_call),
            Some(&setup.state_before_call),
            &Jmp::branch("start1", "end1"),
            &Jmp::branch("start2", "end2"),
            &None,
        )
        .unwrap();

    assert_eq!(None, new_state.get_pointer_inference_state());
    assert_eq!(1, new_state.get_variable_to_pointer_map().len());
    assert_eq!(
        pointer,
        *new_state
            .get_variable_to_pointer_map()
            .get(&callee_saved_reg)
            .unwrap()
    );
}

#[test]
fn test_update_call_stub() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let call_to_memcpy = Jmp::call("jmp1", "memcpy", Some("blk1"));

    let new_state = setup
        .context
        .update_call_stub(&setup.state_before_call, &call_to_memcpy)
        .unwrap();

    assert_eq!(
        CharacterInclusionDomain::ci("str1 str2 str3 str4"),
        *new_state
            .get_stack_offset_to_string_map()
            .get(&-60)
            .unwrap()
    );
}
