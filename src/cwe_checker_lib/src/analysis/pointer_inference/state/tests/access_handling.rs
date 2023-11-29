use super::*;

#[test]
fn handle_store() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&variable!("RSP:8"), Tid::new("time0"), BTreeSet::new());
    let stack_id = new_id("time0", "RSP");
    assert_eq!(
        state.eval(&expr!("RSP:8")),
        Data::from_target(stack_id.clone(), bv(0))
    );

    state.handle_register_assign(&variable!("RSP:8"), &expr!("RSP:8 - 32:8"));
    assert_eq!(
        state.eval(&expr!("RSP:8")),
        Data::from_target(stack_id.clone(), bv(-32))
    );
    state.handle_register_assign(&variable!("RSP:8"), &expr!("RSP:8 + -8:8"));
    assert_eq!(
        state.eval(&expr!("RSP:8")),
        Data::from_target(stack_id.clone(), bv(-40))
    );

    state
        .handle_store(&expr!("RSP:8 + 8:8"), &expr!("1:8"), &global_memory)
        .unwrap();
    state
        .handle_store(&expr!("RSP:8 - 8:8"), &expr!("2:8"), &global_memory)
        .unwrap();
    state
        .handle_store(&expr!("RSP:8 + -16:8"), &expr!("3:8"), &global_memory)
        .unwrap();
    state.handle_register_assign(&variable!("RSP:8"), &expr!("RSP:8 - 4:8"));

    assert_eq!(
        state
            .load_value(&expr!("RSP:8 + 12:8"), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(1).into()
    );
    assert_eq!(
        state
            .load_value(&expr!("RSP:8 - 4:8"), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(2).into()
    );
    assert_eq!(
        state
            .load_value(&expr!("RSP:8 + -12:8"), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(3).into()
    );
}

#[test]
fn global_mem_access() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(
        &variable!("RSP:8"),
        Tid::new("func_tid"),
        BTreeSet::from([0x2000]),
    );
    // global read-only address
    let address_expr = expr!("0x1000:8");
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        bitvec!("0xb3b2b1b0:4").into() // note that we read in little-endian byte order
    );
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::new_top(ByteSize::new(4)),
            &global_memory
        )
        .is_err());
    // global writeable address
    let address_expr = expr!("0x2000:8");
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        DataDomain::new_top(ByteSize::new(4))
    );
    assert!(state
        .write_to_address(&address_expr, &bitvec!("21:4").into(), &global_memory)
        .is_ok());
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        bitvec!("21:4").into()
    );

    // invalid global address
    let address_expr = expr!("0x3456:8");
    assert!(state
        .load_value(&address_expr, ByteSize::new(4), &global_memory)
        .is_err());
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::new_top(ByteSize::new(4)),
            &global_memory
        )
        .is_err());
}

#[test]
fn test_eval_abstract_location() {
    let mut state = State::new(&variable!("RSP:8"), Tid::new("fn_tid"), BTreeSet::new());
    let global_memory = RuntimeMemoryImage::mock();
    let object_id = AbstractIdentifier::mock("fn_tid", "RSI", 8);
    state
        .memory
        .add_abstract_object(object_id.clone(), ByteSize::new(8), None);
    state
        .memory
        .get_object_mut(&state.stack_id)
        .unwrap()
        .set_value(
            Data::from_target(object_id.clone(), bitvec!("0x0:8").into()),
            &bitvec!("0x-20:8").into(),
        )
        .unwrap();
    state
        .memory
        .get_object_mut(&object_id)
        .unwrap()
        .set_value(bitvec!("0x42:8").into(), &bitvec!("0x10:8").into())
        .unwrap();
    let location = AbstractLocation::mock("RSP:8", &[-32], 8);
    let value = state.eval_abstract_location(&location, &global_memory);
    assert_eq!(
        value,
        Data::from_target(object_id.clone(), bitvec!("0x0:8").into())
    );
    let location = AbstractLocation::mock("RSP:8", &[-32, 16], 8);
    let value = state.eval_abstract_location(&location, &global_memory);
    assert_eq!(value, bitvec!("0x42:8").into());
    // Also test evaluation of a global address
    state.memory.get_object_mut(&state.get_global_mem_id().clone()).unwrap().set_value(
        bitvec!("0x43:8").into(), &bitvec!("0x2000:8").into()
    ).unwrap();
    let location = AbstractLocation::mock_global(0x2000, &[0], 8);
    let value = state.eval_abstract_location(&location, &global_memory);
    assert_eq!(value, bitvec!("0x43:8").into());
}
