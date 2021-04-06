use super::*;
use crate::utils::binary::RuntimeMemoryImage;

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(time: &str, register: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(time),
        AbstractLocation::Register(register.into(), ByteSize::new(8)),
    )
}

fn register(name: &str) -> Variable {
    Variable {
        name: name.into(),
        size: ByteSize::new(8),
        is_temp: false,
    }
}

fn reg_add(name: &str, value: i64) -> Expression {
    Expression::Var(register(name)).plus_const(value)
}

fn reg_sub(name: &str, value: i64) -> Expression {
    Expression::BinOp {
        op: BinOpType::IntSub,
        lhs: Box::new(Expression::Var(register(name))),
        rhs: Box::new(Expression::Const(Bitvector::from_i64(value))),
    }
}

#[test]
fn state() {
    use crate::analysis::pointer_inference::object::*;
    use Expression::*;
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("time0", "RSP");
    let stack_addr = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(8)));
    state
        .store_value(&stack_addr, &Data::Value(bv(42)), &global_memory)
        .unwrap();
    state.register.insert(register("RSP"), stack_addr.clone());
    assert_eq!(
        state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        Data::Value(bv(42))
    );

    let mut other_state = State::new(&register("RSP"), Tid::new("time0"));
    state.register.insert(register("RAX"), Data::Value(bv(42)));
    other_state
        .register
        .insert(register("RSP"), stack_addr.clone());
    other_state
        .register
        .insert(register("RAX"), Data::Value(bv(42)));
    other_state
        .register
        .insert(register("RBX"), Data::Value(bv(35)));
    let merged_state = state.merge(&other_state);
    assert_eq!(merged_state.register[&register("RAX")], Data::Value(bv(42)));
    assert_eq!(merged_state.register.get(&register("RBX")), None);
    assert_eq!(
        merged_state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        Data::new_top(ByteSize::new(8))
    );

    // Test pointer adjustment on reads
    state.memory.add_abstract_object(
        new_id("time0", "caller"),
        bv(0),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state.caller_stack_ids.insert(new_id("time0", "caller"));
    state
        .store_value(&stack_addr, &Data::Value(bv(15)), &global_memory)
        .unwrap();
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("time0", "caller"), bv(8))),
                ByteSize::new(8)
            )
            .unwrap(),
        Data::Value(bv(15))
    );
    assert_eq!(
        state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        Data::Value(bv(15))
    );

    // Test replace_abstract_id
    let pointer = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16)));
    state.register.insert(register("RSP"), pointer.clone());
    state
        .store_value(&pointer, &Data::Value(bv(7)), &global_memory)
        .unwrap();
    assert_eq!(
        state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        Data::Value(bv(7))
    );
    state.replace_abstract_id(&stack_id, &new_id("time0", "callee"), &bv(-8));
    assert_eq!(
        state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        Data::Value(bv(7))
    );
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("time0", "callee"), bv(-8))),
                ByteSize::new(8)
            )
            .unwrap(),
        Data::Value(bv(7))
    );
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("time0", "callee"), bv(-16))),
                ByteSize::new(8)
            )
            .unwrap(),
        Data::new_top(ByteSize::new(8))
    );

    state.memory.add_abstract_object(
        new_id("time0", "heap_obj"),
        bv(0),
        ObjectType::Heap,
        ByteSize::new(8),
    );
    assert_eq!(state.memory.get_num_objects(), 3);
    state.remove_unreferenced_objects();
    assert_eq!(state.memory.get_num_objects(), 2);
}

#[test]
fn handle_store() {
    use Expression::*;
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("time0", "RSP");
    assert_eq!(
        state.eval(&Var(register("RSP"))).unwrap(),
        Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0)))
    );

    state
        .handle_register_assign(&register("RSP"), &reg_sub("RSP", 32))
        .unwrap();
    assert_eq!(
        state.eval(&Var(register("RSP"))).unwrap(),
        Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-32)))
    );
    state
        .handle_register_assign(&register("RSP"), &reg_add("RSP", -8))
        .unwrap();
    assert_eq!(
        state.eval(&Var(register("RSP"))).unwrap(),
        Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-40)))
    );

    state
        .handle_store(
            &reg_add("RSP", 8),
            &Const(Bitvector::from_i64(1)),
            &global_memory,
        )
        .unwrap();
    state
        .handle_store(
            &reg_sub("RSP", 8),
            &Const(Bitvector::from_i64(2)),
            &global_memory,
        )
        .unwrap();
    state
        .handle_store(
            &reg_add("RSP", -16),
            &Const(Bitvector::from_i64(3)),
            &global_memory,
        )
        .unwrap();
    state
        .handle_register_assign(&register("RSP"), &reg_sub("RSP", 4))
        .unwrap();

    assert_eq!(
        state
            .load_value(&reg_add("RSP", 12), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(1).into()
    );
    assert_eq!(
        state
            .load_value(&reg_sub("RSP", 4), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(2).into()
    );
    assert_eq!(
        state
            .load_value(&reg_add("RSP", -12), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(3).into()
    );
}

#[test]
fn handle_caller_stack_stores() {
    use super::super::object::ObjectType;
    use Expression::*;
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    state.memory.add_abstract_object(
        new_id("caller1", "RSP"),
        bv(0),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state.memory.add_abstract_object(
        new_id("caller2", "RSP"),
        bv(0),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state.caller_stack_ids.insert(new_id("caller1", "RSP"));
    state.caller_stack_ids.insert(new_id("caller2", "RSP"));
    // store something on the caller stack
    state
        .handle_store(
            &reg_add("RSP", 8),
            &Const(Bitvector::from_i64(42)),
            &global_memory,
        )
        .unwrap();
    // check that it was saved in all caller objects and not on the callee stack object
    let pointer = PointerDomain::new(new_id("time0", "RSP"), bv(8)).into();
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)).unwrap(),
        Data::new_top(ByteSize::new(8))
    );
    let pointer = PointerDomain::new(new_id("caller1", "RSP"), bv(8)).into();
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)).unwrap(),
        bv(42).into()
    );
    let pointer = PointerDomain::new(new_id("caller2", "RSP"), bv(8)).into();
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)).unwrap(),
        bv(42).into()
    );
    // accessing through a positive stack register offset should yield the value of the caller stacks
    assert_eq!(
        state
            .load_value(&reg_add("RSP", 8), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(42).into()
    );
}

#[test]
fn clear_parameters_on_the_stack_on_extern_calls() {
    use Expression::*;
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    state.register.insert(
        register("RSP"),
        PointerDomain::new(new_id("time0", "RSP"), bv(-20)).into(),
    );
    // write something onto the stack
    state
        .handle_store(
            &reg_add("RSP", 8),
            &Const(Bitvector::from_i64(42)),
            &global_memory,
        )
        .unwrap();
    // create an extern symbol which uses the value on the stack as a parameter
    let stack_param = Arg::Stack {
        offset: 8,
        size: ByteSize::new(8),
    };
    let extern_symbol = ExternSymbol {
        tid: Tid::new("symbol"),
        addresses: vec![],
        name: "my_extern_symbol".into(),
        calling_convention: None,
        parameters: vec![stack_param],
        return_values: Vec::new(),
        no_return: false,
    };
    // check the value before
    let pointer = PointerDomain::new(new_id("time0", "RSP"), bv(-12)).into();
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)).unwrap(),
        bv(42).into()
    );
    // clear stack parameter
    state
        .clear_stack_parameter(&extern_symbol, &register("RSP"), &global_memory)
        .unwrap();
    // check the value after
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)).unwrap(),
        Data::new_top(ByteSize::new(8))
    );
}

#[test]
fn merge_callee_stack_to_caller_stack() {
    use super::super::object::ObjectType;
    let mut state = State::new(&register("RSP"), Tid::new("callee"));
    state.memory.add_abstract_object(
        new_id("callsite", "RSP"),
        bv(52),
        ObjectType::Stack,
        ByteSize::new(8),
    );
    state.caller_stack_ids.insert(new_id("callsite", "RSP"));
    // check the state before merging to the caller stack
    assert_eq!(
        state.register.get(&register("RSP")).unwrap(),
        &PointerDomain::new(new_id("callee", "RSP"), bv(0)).into()
    );
    assert_eq!(state.memory.get_all_object_ids().len(), 2);
    // check state after merging to the caller stack
    state.merge_callee_stack_to_caller_stack(
        &new_id("callee", "RSP"),
        &new_id("callsite", "RSP"),
        &bv(-52),
    );
    assert_eq!(
        state.register.get(&register("RSP")).unwrap(),
        &PointerDomain::new(new_id("callsite", "RSP"), bv(52)).into()
    );
    assert_eq!(state.memory.get_all_object_ids().len(), 1);
}

#[test]
fn remove_and_restore_callee_saved_register() {
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let value: Data = Bitvector::from_u64(42).into();
    let cconv = CallingConvention::mock();
    state.set_register(&register("RBP"), value.clone());
    state.set_register(&register("RAX"), value.clone());

    let mut callee_state = state.clone();
    callee_state.remove_callee_saved_register(&cconv);
    assert_eq!(
        callee_state.get_register(&register("RBP")).unwrap(),
        Data::new_top(ByteSize::new(8))
    );
    assert_eq!(
        callee_state.get_register(&register("RAX")).unwrap(),
        value.clone()
    );

    let other_value: Data = Bitvector::from_u64(13).into();
    callee_state.set_register(&register("RAX"), other_value.clone());
    callee_state.restore_callee_saved_register(&state, &cconv, &register("RSP"));
    assert_eq!(callee_state.get_register(&register("RBP")).unwrap(), value);
    assert_eq!(
        callee_state.get_register(&register("RAX")).unwrap(),
        other_value
    );
}

#[test]
fn reachable_ids_under_and_overapproximation() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let stack_id = new_id("func_tid", "RSP");
    let heap_id = new_id("heap_obj", "RAX");
    let stack_address: Data =
        PointerDomain::new(stack_id.clone(), Bitvector::from_i64(-8).into()).into();
    let heap_address: Data =
        PointerDomain::new(heap_id.clone(), Bitvector::from_i64(0).into()).into();
    // Add the heap object to the state, so that it can be recursively searched.
    state.memory.add_abstract_object(
        heap_id.clone(),
        Bitvector::from_i64(0).into(),
        crate::analysis::pointer_inference::object::ObjectType::Heap,
        ByteSize::new(8),
    );

    state
        .store_value(&stack_address, &heap_address, &global_memory)
        .unwrap();
    let reachable_ids: BTreeSet<AbstractIdentifier> = vec![stack_id.clone()].into_iter().collect();
    assert_eq!(
        state.add_directly_reachable_ids_to_id_set(reachable_ids.clone()),
        vec![stack_id.clone(), heap_id.clone()]
            .into_iter()
            .collect()
    );
    assert_eq!(
        state.add_recursively_referenced_ids_to_id_set(reachable_ids.clone()),
        vec![stack_id.clone(), heap_id.clone()]
            .into_iter()
            .collect()
    );

    let _ = state.store_value(
        &PointerDomain::new(stack_id.clone(), ValueDomain::new_top(ByteSize::new(8))).into(),
        &Data::Value(Bitvector::from_i64(42).into()),
        &global_memory,
    );
    assert_eq!(
        state.add_directly_reachable_ids_to_id_set(reachable_ids.clone()),
        vec![stack_id.clone()].into_iter().collect()
    );
    assert_eq!(
        state.add_recursively_referenced_ids_to_id_set(reachable_ids.clone()),
        vec![stack_id.clone(), heap_id.clone()]
            .into_iter()
            .collect()
    );
}

#[test]
fn global_mem_access() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));

    // global read-only address
    let address_expr = Expression::Const(Bitvector::from_u64(0x1000));
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        DataDomain::Value(Bitvector::from_u32(0xb3b2b1b0).into()) // note that we read in little-endian byte order
    );
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::Top(ByteSize::new(4)),
            &global_memory
        )
        .is_err());

    // global writeable address
    let address_expr = Expression::Const(Bitvector::from_u64(0x2000));
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        DataDomain::Top(ByteSize::new(4))
    );
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::Top(ByteSize::new(4)),
            &global_memory
        )
        .is_ok());

    // invalid global address
    let address_expr = Expression::Const(Bitvector::from_u64(0x3456));
    assert!(state
        .load_value(&address_expr, ByteSize::new(4), &global_memory)
        .is_err());
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::Top(ByteSize::new(4)),
            &global_memory
        )
        .is_err());
}
