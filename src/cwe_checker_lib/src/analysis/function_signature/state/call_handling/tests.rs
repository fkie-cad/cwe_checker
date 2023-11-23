use super::*;
use crate::{bitvec, variable};

#[test]
fn test_generate_return_values_for_call() {
    let mut state = State::mock_arm32();
    let input_ids = BTreeSet::from([
        AbstractIdentifier::mock("mock_fn", "r0", 4),
        AbstractIdentifier::mock("mock_fn", "big_register", 16),
    ]);
    let return_args = [Arg::mock_register("r1", 4)];
    let call_tid = Tid::new("call");
    state.generate_return_values_for_call(&input_ids, &return_args, &call_tid);
    assert!(state
        .tracked_ids
        .get(&AbstractIdentifier::mock("call", "r1", 4))
        .is_some());
    let expected_return_value = DataDomain::mock_from_target_map(BTreeMap::from([
        (
            AbstractIdentifier::mock("mock_fn", "r0", 4),
            BitvectorDomain::new_top(ByteSize::new(4)),
        ),
        (
            AbstractIdentifier::mock("call", "r1", 4),
            bitvec!("0x0:4").into(),
        ),
    ]));
    assert_eq!(state.register[&variable!("r1:4")], expected_return_value);
}

#[test]
fn test_get_params_of_current_function() {
    let mut state = State::mock_arm32();
    let param_one = AbstractIdentifier::mock("mock_fn", "param_one", 4);
    let param_two = AbstractIdentifier::mock("mock_fn", "param_two", 4);
    let not_param = AbstractIdentifier::mock("call_tid", "r0", 4);
    let non_param_stack_offset = AbstractIdentifier::new(
        Tid::new("mock_fn"),
        AbstractLocation::mock("sp:4", &[-8], 4),
    );
    let global_param = AbstractIdentifier::new(
        Tid::new("mock_fn"),
        AbstractLocation::GlobalAddress {
            address: 0x1000,
            size: ByteSize::new(4),
        },
    );
    state
        .tracked_ids
        .insert(param_one.clone(), AccessPattern::new().with_read_flag());
    state.tracked_ids.insert(
        param_two.clone(),
        AccessPattern::new().with_dereference_flag(),
    );
    state
        .tracked_ids
        .insert(not_param, AccessPattern::new_unknown_access());
    state
        .tracked_ids
        .insert(non_param_stack_offset, AccessPattern::new_unknown_access());
    state
        .tracked_ids
        .insert(global_param.clone(), AccessPattern::new_unknown_access());
    let params = state.get_params_of_current_function();
    let global_params = state.get_global_mem_params_of_current_function();
    assert_eq!(
        params,
        Vec::from([
            (
                param_one.get_location(),
                AccessPattern::new().with_read_flag()
            ),
            (
                param_two.get_location(),
                AccessPattern::new().with_dereference_flag()
            )
        ])
    );
    assert_eq!(
        global_params,
        Vec::from([(
            global_param.get_location(),
            AccessPattern::new_unknown_access()
        )])
    );
}

#[test]
fn test_merge_parameter_access() {
    let mut state = State::mock_arm32();
    let num_original_tracked_ids = state.tracked_ids.len();
    let global_memory = RuntimeMemoryImage::mock();
    state.register.insert(
        variable!("sp:4"),
        DataDomain::from_target(state.stack_id.clone(), bitvec!("0x-20:4").into()),
    );
    state.register.insert(
        variable!("r1:4"),
        DataDomain::from_target(
            AbstractIdentifier::mock("mock_fn", "r0", 4),
            bitvec!("0x2:4").into(),
        ),
    );
    let param_loc = AbstractLocation::mock("r0:4", &[], 4);
    let stack_param_loc = AbstractLocation::mock("sp:4", &[0], 4);
    let high_stack_param_loc = AbstractLocation::mock("sp:4", &[32], 4);
    let nested_param_loc = AbstractLocation::mock("r1:4", &[6], 4);
    let params = [
        (&param_loc, AccessPattern::new_unknown_access()),
        (&stack_param_loc, AccessPattern::new_unknown_access()),
        (&high_stack_param_loc, AccessPattern::new_unknown_access()),
        (&nested_param_loc, AccessPattern::new_unknown_access()),
    ];
    state.merge_parameter_access(&params, &global_memory);
    // Merge normal param access
    assert_eq!(
        state
            .tracked_ids
            .get(&AbstractIdentifier::new(
                Tid::new("mock_fn"),
                param_loc.clone()
            ))
            .unwrap(),
        &AccessPattern::new_unknown_access()
    );
    // Do not merge/track access to local stack variable
    assert!(state
        .tracked_ids
        .get(&AbstractIdentifier::new(
            Tid::new("mock_fn"),
            AbstractLocation::mock("sp:4", &[-32], 4)
        ))
        .is_none());
    // Generate new stack param if necessary
    assert_eq!(
        state
            .tracked_ids
            .get(&AbstractIdentifier::new(
                Tid::new("mock_fn"),
                AbstractLocation::mock("sp:4", &[0], 4)
            ))
            .unwrap(),
        &AccessPattern::new_unknown_access()
    );
    // Track new nested parameter (in the right register)
    assert_eq!(
        state
            .tracked_ids
            .get(&AbstractIdentifier::new(
                Tid::new("mock_fn"),
                AbstractLocation::mock("r0:4", &[8], 4)
            ))
            .unwrap(),
        &AccessPattern::new_unknown_access()
    );
    assert_eq!(state.tracked_ids.len(), num_original_tracked_ids + 2);
}

#[test]
fn test_eval_param_location() {
    let mut state = State::mock_arm32();
    let global_memory = RuntimeMemoryImage::mock();
    // Param is a register
    state
        .register
        .insert(variable!("r0:4"), bitvec!("0x123:4").into());
    let value = state.eval_param_location(&AbstractLocation::mock("r0:4", &[], 4), &global_memory);
    assert_eq!(value, bitvec!("0x123:4").into());
    // Param is a nested register (and values in nested objects are not tracked)
    state.register.insert(
        variable!("r0:4"),
        DataDomain::from_target(
            AbstractIdentifier::mock("mock_fn", "r3", 4),
            bitvec!("0x0:4").into(),
        ),
    );
    let value = state.eval_param_location(&AbstractLocation::mock("r0:4", &[8], 4), &global_memory);
    assert_eq!(
        value,
        DataDomain::from_target(
            AbstractIdentifier::new(Tid::new("mock_fn"), AbstractLocation::mock("r3:4", &[8], 4)),
            bitvec!("0x0:4").into()
        )
    );
    // Read the value at a stack offset
    state
        .stack
        .insert_at_byte_index(bitvec!("0x42:4").into(), -8);
    let value =
        state.eval_param_location(&AbstractLocation::mock("sp:4", &[-8], 4), &global_memory);
    assert_eq!(value, bitvec!("0x42:4").into());
    // Read a nested pointer from the stack. The read has to remove one level of indirection if the stack value can be read.
    state.stack.insert_at_byte_index(
        DataDomain::from_target(
            AbstractIdentifier::mock("mock_fn", "r0", 4),
            bitvec!("0x5:4").into(),
        ),
        -8,
    );
    let value = state.eval_param_location(
        &AbstractLocation::mock("sp:4", &[-8, 2, 6], 4),
        &global_memory,
    );
    assert_eq!(
        value,
        DataDomain::from_target(
            AbstractIdentifier::new(
                Tid::new("mock_fn"),
                AbstractLocation::mock("r0:4", &[7, 6], 4)
            ),
            bitvec!("0x0:4").into()
        )
    );
}
