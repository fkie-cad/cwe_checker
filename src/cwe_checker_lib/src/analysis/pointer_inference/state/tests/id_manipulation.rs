use super::*;

#[test]
fn test_map_abstract_locations_to_pointer_data() {
    let call_tid = Tid::new("call");
    let global_memory = RuntimeMemoryImage::mock();
    let full_access = AccessPattern::new_unknown_access();
    let fn_sig = FunctionSignature {
        parameters: BTreeMap::from([(AbstractLocation::mock("r0:4", &[], 4), full_access)]),
        global_parameters: BTreeMap::from([(
            AbstractLocation::mock_global(0x2000, &[], 4),
            full_access,
        )]),
    };
    let mut state = State::from_fn_sig(&fn_sig, &variable!("sp:4"), Tid::new("callee"));
    let param_id =
        AbstractIdentifier::new(Tid::new("callee"), AbstractLocation::mock("r0:4", &[], 4));
    let param_pointer = Data::from_target(param_id.clone(), bitvec!("0x2:4").into());
    let global_param_pointer = Data::from_target(
        state.get_global_mem_id().clone(),
        bitvec!("0x2000:4").into(),
    );
    let callee_orig_id = AbstractIdentifier::new(
        Tid::new("inside_callee"),
        AbstractLocation::mock("r0:4", &[], 4),
    );
    let callee_orig_pointer = Data::from_target(callee_orig_id.clone(), bitvec!("0x3:4").into());
    let nested_callee_orig_id = AbstractIdentifier::new(
        Tid::new("inside_callee"),
        AbstractLocation::mock("r0:4", &[0x10], 4),
    );
    let nested_callee_orig_pointer =
        Data::from_target(nested_callee_orig_id.clone(), bitvec!("0x0:4").into());
    state
        .memory
        .add_abstract_object(callee_orig_id.clone(), ByteSize::new(4), None);
    state
        .memory
        .add_abstract_object(nested_callee_orig_id.clone(), ByteSize::new(4), None);
    state
        .store_value(&param_pointer, &nested_callee_orig_pointer, &global_memory)
        .unwrap();
    state
        .store_value(
            &global_param_pointer,
            &nested_callee_orig_pointer,
            &global_memory,
        )
        .unwrap();
    state.set_register(&variable!("r0:4"), callee_orig_pointer.clone());
    state
        .store_value(
            &callee_orig_pointer,
            &nested_callee_orig_pointer,
            &global_memory,
        )
        .unwrap();
    let location_to_data_map = state.map_abstract_locations_to_pointer_data(&call_tid);
    let expected_map = BTreeMap::from([
        (
            AbstractIdentifier::new(
                Tid::new("call_param"),
                AbstractLocation::mock("r0:4", &[2], 4),
            ),
            nested_callee_orig_pointer.clone(),
        ),
        (
            AbstractIdentifier::new(
                Tid::new("call_param"),
                AbstractLocation::mock_global(0x0, &[0x2000], 4),
            ),
            nested_callee_orig_pointer.clone(),
        ),
        (
            AbstractIdentifier::new(Tid::new("call"), AbstractLocation::mock("r0:4", &[], 4)),
            callee_orig_pointer.clone(),
        ),
        (
            AbstractIdentifier::new(Tid::new("call"), AbstractLocation::mock("r0:4", &[0], 4)),
            nested_callee_orig_pointer.clone(),
        ),
    ]);
    assert_eq!(location_to_data_map, expected_map);
}

#[test]
fn test_filter_location_to_data_map() {
    let full_access = AccessPattern::new_unknown_access();
    let fn_sig = FunctionSignature {
        parameters: BTreeMap::from([(AbstractLocation::mock("r0:4", &[], 4), full_access)]),
        global_parameters: BTreeMap::from([(
            AbstractLocation::mock_global(0x2000, &[], 4),
            full_access,
        )]),
    };
    let mut state = State::from_fn_sig(&fn_sig, &variable!("sp:4"), Tid::new("callee"));
    state.memory.add_abstract_object(
        AbstractIdentifier::mock("callee_orig", "r0", 4),
        ByteSize::new(4),
        None,
    );
    state.memory.add_abstract_object(
        AbstractIdentifier::mock("callee_orig_2", "r0", 4),
        ByteSize::new(4),
        None,
    );
    state.memory.add_abstract_object(
        AbstractIdentifier::mock("callee_orig_3", "r0", 4),
        ByteSize::new(4),
        None,
    );
    let mut loc_to_data_map = BTreeMap::from([
        (
            AbstractIdentifier::mock("call", "r0", 4),
            Data::mock_from_target_map(BTreeMap::from([
                (
                    AbstractIdentifier::mock("callee", "r0", 4),
                    bitvec!("0x0:4").into(),
                ),
                (
                    AbstractIdentifier::mock("callee_orig", "r0", 4),
                    bitvec!("0x0:4").into(),
                ),
                (
                    AbstractIdentifier::mock("callee_orig_3", "r0", 4),
                    bitvec!("0x0:4").into(),
                ),
            ])),
        ),
        (
            AbstractIdentifier::mock("call", "r1", 4),
            Data::mock_from_target_map(BTreeMap::from([
                (
                    AbstractIdentifier::mock("callee", "r0", 4),
                    bitvec!("0x0:4").into(),
                ),
                (
                    AbstractIdentifier::mock("callee_orig_2", "r0", 4),
                    bitvec!("0x0:4").into(),
                ),
            ])),
        ),
        (
            AbstractIdentifier::mock("call", "r2", 4),
            Data::mock_from_target_map(BTreeMap::from([(
                AbstractIdentifier::mock("callee_orig_2", "r0", 4),
                bitvec!("0x0:4").into(),
            )])),
        ),
    ]);
    state.filter_location_to_pointer_data_map(&mut loc_to_data_map);
    let expected_map = BTreeMap::from([(
        AbstractIdentifier::mock("call", "r0", 4),
        Data::mock_from_target_map(BTreeMap::from([
            (
                AbstractIdentifier::mock("callee", "r0", 4),
                bitvec!("0x0:4").into(),
            ),
            (
                AbstractIdentifier::mock("callee_orig", "r0", 4),
                bitvec!("0x0:4").into(),
            ),
            (
                AbstractIdentifier::mock("callee_orig_3", "r0", 4),
                bitvec!("0x0:4").into(),
            ),
        ])),
    )]);
    assert_eq!(loc_to_data_map, expected_map);
}

#[test]
fn test_generate_target_objects_for_new_locations() {
    let global_memory = RuntimeMemoryImage::mock();
    let full_access = AccessPattern::new_unknown_access();
    let fn_sig = FunctionSignature {
        parameters: BTreeMap::from([(AbstractLocation::mock("r0:4", &[], 4), full_access)]),
        global_parameters: BTreeMap::from([(
            AbstractLocation::mock_global(0x2000, &[], 4),
            full_access,
        )]),
    };
    let mut state = State::from_fn_sig(&fn_sig, &variable!("sp:4"), Tid::new("callee"));
    let param_id = AbstractIdentifier::mock("callee", "r0", 4);
    let callee_orig_id = AbstractIdentifier::mock("callee_orig", "r0", 4);
    let callee_orig_2_id = AbstractIdentifier::mock("callee_orig_2", "r0", 4);
    state
        .memory
        .add_abstract_object(callee_orig_id.clone(), ByteSize::new(4), None);
    state
        .memory
        .add_abstract_object(callee_orig_2_id.clone(), ByteSize::new(4), None);
    state
        .store_value(
            &Data::from_target(param_id.clone(), bitvec!("0x0:4").into()),
            &bitvec!("0x42:4").into(),
            &global_memory,
        )
        .unwrap();
    state
        .store_value(
            &Data::from_target(callee_orig_id.clone(), bitvec!("0x4:4").into()),
            &bitvec!("0x24:4").into(),
            &global_memory,
        )
        .unwrap();
    let loc_to_data_map = BTreeMap::from([(
        AbstractIdentifier::mock("call", "r0", 4),
        Data::mock_from_target_map(BTreeMap::from([
            (param_id.clone(), bitvec!("0x0:4").into()),
            (callee_orig_id.clone(), bitvec!("0x0:4").into()),
            (callee_orig_2_id.clone(), bitvec!("0x0:4").into()),
        ])),
    )]);
    let loc_to_obj_map = state.generate_target_objects_for_new_locations(&loc_to_data_map);
    assert_eq!(loc_to_obj_map.len(), 1);
    let object = &loc_to_obj_map[&AbstractIdentifier::mock("call", "r0", 4)];
    assert_eq!(
        object.get_value(bitvec!("0x0:4"), ByteSize::new(4)),
        Data::new_top(ByteSize::new(4))
    );
    let mut merged_value = Data::new_top(ByteSize::new(4));
    merged_value.set_absolute_value(Some(bitvec!("0x24:4").into()));
    assert_eq!(
        object.get_value(bitvec!("0x4:4"), ByteSize::new(4)),
        merged_value
    );
}

#[test]
fn test_get_id_to_unified_id_replacement_map() {
    let cconv = CallingConvention::mock_arm32();
    let full_access = AccessPattern::new_unknown_access();
    let fn_sig = FunctionSignature {
        parameters: BTreeMap::from([(AbstractLocation::mock("r0:4", &[], 4), full_access)]),
        global_parameters: BTreeMap::from([(
            AbstractLocation::mock_global(0x2000, &[], 4),
            full_access,
        )]),
    };
    let mut state = State::from_fn_sig(&fn_sig, &variable!("sp:4"), Tid::new("callee"));
    state.minimize_before_return_instruction(&fn_sig, &cconv);
    let location_to_data_map = BTreeMap::from([(
        AbstractIdentifier::mock("call", "r0", 4),
        Data::mock_from_target_map(BTreeMap::from([
            (
                AbstractIdentifier::mock("callee", "r0", 4),
                bitvec!("0x2:4").into(),
            ),
            (
                AbstractIdentifier::mock("callee_orig", "r0", 4),
                bitvec!("0x3:4").into(),
            ),
            (
                AbstractIdentifier::mock("callee_orig_2", "r0", 4),
                bitvec!("0x4:4").into(),
            ),
        ])),
    )]);
    let id_replacement_map = state.get_id_to_unified_ids_replacement_map(&location_to_data_map);
    let merged_id = AbstractIdentifier::mock("call", "r0", 4);
    let mut merged_pointer = Data::from_target(merged_id.clone(), bitvec!("0x-3:4").into());
    merged_pointer.set_contains_top_flag();
    let mut merged_pointer_2 = Data::from_target(merged_id.clone(), bitvec!("0x-4:4").into());
    merged_pointer_2.set_contains_top_flag();
    let param_id = AbstractIdentifier::mock("callee", "r0", 4);
    let expected_map = BTreeMap::from([
        (
            AbstractIdentifier::mock("callee_orig", "r0", 4),
            merged_pointer,
        ),
        (
            AbstractIdentifier::mock("callee_orig_2", "r0", 4),
            merged_pointer_2,
        ),
        (
            param_id.clone(),
            Data::from_target(param_id, bitvec!("0x0:4").into()),
        ),
    ]);
    assert_eq!(id_replacement_map, expected_map);
}

#[test]
fn test_insert_pointers_to_unified_objects() {
    todo!();
}
