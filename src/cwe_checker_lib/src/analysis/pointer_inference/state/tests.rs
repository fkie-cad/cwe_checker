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
        state.eval(&Var(register("RSP"))),
        Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0)))
    );

    state.handle_register_assign(&register("RSP"), &reg_sub("RSP", 32));
    assert_eq!(
        state.eval(&Var(register("RSP"))),
        Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-32)))
    );
    state.handle_register_assign(&register("RSP"), &reg_add("RSP", -8));
    assert_eq!(
        state.eval(&Var(register("RSP"))),
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
    state.handle_register_assign(&register("RSP"), &reg_sub("RSP", 4));

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
        data_type: None,
    };
    let extern_symbol = ExternSymbol {
        tid: Tid::new("symbol"),
        addresses: vec![],
        name: "my_extern_symbol".into(),
        calling_convention: None,
        parameters: vec![stack_param],
        return_values: Vec::new(),
        no_return: false,
        has_var_args: false,
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
        callee_state.get_register(&register("RBP")),
        Data::new_top(ByteSize::new(8))
    );
    assert_eq!(callee_state.get_register(&register("RAX")), value.clone());

    let other_value: Data = Bitvector::from_u64(13).into();
    callee_state.set_register(&register("RAX"), other_value.clone());
    callee_state.restore_callee_saved_register(&state, &cconv, &register("RSP"));
    assert_eq!(callee_state.get_register(&register("RBP")), value);
    assert_eq!(callee_state.get_register(&register("RAX")), other_value);
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

/// Test expression specialization except for binary operations.
#[test]
fn specialize_by_expression_results() {
    let mut base_state = State::new(&register("RSP"), Tid::new("func_tid"));
    base_state.set_register(
        &register("RAX"),
        IntervalDomain::new(Bitvector::from_i64(5), Bitvector::from_i64(10)).into(),
    );

    // Expr = Var(RAX)
    let mut state = base_state.clone();
    let x = state
        .specialize_by_expression_result(&Expression::var("RAX", 8), Bitvector::from_i64(7).into());
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(7).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8),
        Bitvector::from_i64(-20).into(),
    );
    assert!(x.is_err());

    let mut state = base_state.clone();
    let abstract_id = AbstractIdentifier::new(
        Tid::new("heap_obj"),
        AbstractLocation::from_var(&register("RAX")).unwrap(),
    );
    state.set_register(
        &register("RAX"),
        PointerDomain::new(abstract_id.clone(), IntervalDomain::mock(0, 50)).into(),
    );
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8),
        PointerDomain::new(abstract_id.clone(), IntervalDomain::mock(20, 70)).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        PointerDomain::new(abstract_id, IntervalDomain::mock(20, 50)).into()
    );

    // Expr = Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::Const(Bitvector::from_i64(-20)),
        Bitvector::from_i64(-20).into(),
    );
    assert!(x.is_ok());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::Const(Bitvector::from_i64(5)),
        Bitvector::from_i64(-20).into(),
    );
    assert!(x.is_err());

    // Expr = -Var(RAX)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8).un_op(UnOpType::Int2Comp),
        Bitvector::from_i64(-7).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(7).into()
    );

    // Expr = IntSExt(Var(EAX))
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let eax_register = Variable {
        name: "EAX".to_string(),
        size: ByteSize::new(4),
        is_temp: false,
    };
    state.set_register(
        &eax_register,
        IntervalDomain::new(Bitvector::from_i32(-10), Bitvector::from_i32(-5)).into(),
    );
    let x = state.specialize_by_expression_result(
        &Expression::Var(eax_register.clone()).cast(CastOpType::IntSExt),
        Bitvector::from_i64(-7).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&eax_register),
        Bitvector::from_i32(-7).into()
    );

    // Expr = Subpiece(Var(RAX))
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let rax_register = Variable {
        name: "RAX".to_string(),
        size: ByteSize::new(8),
        is_temp: false,
    };
    let x = state.specialize_by_expression_result(
        &Expression::Var(rax_register.clone()).subpiece(ByteSize::new(0), ByteSize::new(1)),
        Bitvector::from_i8(5).into(),
    );
    assert!(x.is_ok());
    assert!(state.get_register(&rax_register).is_top());
    state.set_register(&rax_register, IntervalDomain::mock(3, 10).into());
    let x = state.specialize_by_expression_result(
        &Expression::Var(rax_register.clone()).subpiece(ByteSize::new(0), ByteSize::new(1)),
        Bitvector::from_i8(5).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&rax_register),
        IntervalDomain::mock(5, 5).into()
    );
}

/// Test expression specialization for binary operations
/// except equality and inequality operations
#[test]
fn specialize_by_binop() {
    let base_state = State::new(&register("RSP"), Tid::new("func_tid"));

    // Expr = RAX + Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8).plus_const(20),
        IntervalDomain::mock(5, 7).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(-15, -13).into()
    );

    // Expr = RAX - Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8).minus_const(20),
        Bitvector::from_i64(5).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(25).into()
    );

    // Expr = RAX xor Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::var("RAX", 8)),
            op: BinOpType::IntXOr,
            rhs: Box::new(Expression::const_from_i64(3)),
        },
        Bitvector::from_i64(-1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(-4).into()
    );

    // Expr = (RAX or RBX == 0)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::var("RAX", 8)),
            op: BinOpType::IntOr,
            rhs: Box::new(Expression::var("RBX", 8)),
        },
        Bitvector::from_i64(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(0).into()
    );
    assert_eq!(
        state.get_register(&register("RBX")),
        Bitvector::from_i64(0).into()
    );
    // Expr = (RAX or 0 == Const)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::var("RAX", 8)),
            op: BinOpType::IntOr,
            rhs: Box::new(Expression::const_from_i64(0)),
        },
        Bitvector::from_i64(42).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(42).into()
    );

    // Expr = (FLAG1 bool_and FLAG2 == 1)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(Variable::mock("FLAG1", 1u64))),
            op: BinOpType::BoolAnd,
            rhs: Box::new(Expression::Var(Variable::mock("FLAG2", 1u64))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&Variable::mock("FLAG1", 1u64)),
        Bitvector::from_u8(1).into()
    );
    assert_eq!(
        state.get_register(&Variable::mock("FLAG2", 1u64)),
        Bitvector::from_u8(1).into()
    );
    // Expr = (FLAG bool_and 1 = Const)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Const(Bitvector::from_u8(1))),
            op: BinOpType::BoolAnd,
            rhs: Box::new(Expression::Var(Variable::mock("FLAG", 1u64))),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&Variable::mock("FLAG", 1u64)),
        Bitvector::from_u8(0).into()
    );
}

/// Test expression specialization for comparison operations `==` and `!=`.
#[test]
fn specialize_by_equality_comparison() {
    let mut base_state = State::new(&register("RSP"), Tid::new("func_tid"));
    base_state.set_register(&register("RAX"), IntervalDomain::mock(0, 50).into());

    // Expr = RAX == Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(23)),
            op: BinOpType::IntEqual,
            rhs: Box::new(Expression::var("RAX", 8)),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(23).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(23)),
            op: BinOpType::IntNotEqual,
            rhs: Box::new(Expression::var("RAX", 8)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(23).into()
    );

    // Expr = RAX != Const
    let mut state = base_state.clone();
    state.set_register(&register("RAX"), Bitvector::from_i64(23).into());
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(23)),
            op: BinOpType::IntNotEqual,
            rhs: Box::new(Expression::var("RAX", 8)),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(100)),
            op: BinOpType::IntEqual,
            rhs: Box::new(Expression::var("RAX", 8)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 0, 50, Some(99)).into()
    );
}

/// Test expression specialization for signed comparison operations `<` and `<=`.
#[test]
fn specialize_by_signed_comparison_op() {
    let mut base_state = State::new(&register("RSP"), Tid::new("func_tid"));
    let interval = IntervalDomain::mock(5, 10);
    base_state.set_register(&register("RAX"), interval.into());

    // Expr = RAX < Const (signed)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(7)),
            op: BinOpType::IntSLess,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(8, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(15)),
            op: BinOpType::IntSLess,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 5, 10, Some(15)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntSLess,
            rhs: Box::new(Expression::Const(Bitvector::signed_min_value(
                ByteSize::new(8).into(),
            ))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntSLess,
            rhs: Box::new(Expression::const_from_i64(7)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(7, 10).into()
    );

    // Expr = RAX <= Const (signed)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(7)),
            op: BinOpType::IntSLessEqual,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(7, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(15)),
            op: BinOpType::IntSLessEqual,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 5, 10, Some(14)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntSLessEqual,
            rhs: Box::new(Expression::Const(Bitvector::signed_min_value(
                ByteSize::new(8).into(),
            ))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntSLessEqual,
            rhs: Box::new(Expression::const_from_i64(7)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(8, 10).into()
    );
}

/// Test expression specialization for unsigned comparison operations `<` and `<=`.
#[test]
fn specialize_by_unsigned_comparison_op() {
    let mut base_state = State::new(&register("RSP"), Tid::new("func_tid"));
    let interval = IntervalDomain::mock(-5, 10);
    base_state.set_register(&register("RAX"), interval.into());

    // Expr = RAX < Const (unsigned)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(7)),
            op: BinOpType::IntLess,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(-5, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(15)),
            op: BinOpType::IntLess,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 0, 10, Some(15)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntLess,
            rhs: Box::new(Expression::const_from_i64(0)),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntLess,
            rhs: Box::new(Expression::const_from_i64(-20)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(Some(-20), -5, -1, None).into()
    );

    // Expr = RAX <= Const (unsigned)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(7)),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock(-5, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::const_from_i64(15)),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(Expression::Var(register("RAX"))),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(None, 0, 10, Some(14)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(Expression::const_from_i64(0)),
        },
        Bitvector::from_u8(1).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Bitvector::from_i64(0).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(Expression::const_from_i64(-20)),
        },
        Bitvector::from_u8(0).into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        IntervalDomain::mock_with_bounds(Some(-19), -5, -1, None).into()
    );
}

#[test]
fn stack_pointer_with_nonnegative_offset() {
    let state = State::new(&register("RSP"), Tid::new("func_tid"));
    let pointer = PointerDomain::new(state.stack_id.clone(), Bitvector::from_i64(-1).into()).into();
    assert!(!state.is_stack_pointer_with_nonnegative_offset(&pointer));
    let pointer = PointerDomain::new(state.stack_id.clone(), Bitvector::from_i64(5).into()).into();
    assert!(state.is_stack_pointer_with_nonnegative_offset(&pointer));
    let pointer = PointerDomain::new(state.stack_id.clone(), IntervalDomain::mock(2, 3)).into();
    assert!(!state.is_stack_pointer_with_nonnegative_offset(&pointer)); // The offset is not a constant
}

#[test]
fn out_of_bounds_access_recognition() {
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let global_data = RuntimeMemoryImage::mock();
    let heap_obj_id = new_id("heap_malloc", "RAX");
    state.memory.add_abstract_object(
        heap_obj_id.clone(),
        Bitvector::from_u64(0).into(),
        crate::analysis::pointer_inference::object::ObjectType::Heap,
        ByteSize::new(8),
    );
    state
        .memory
        .set_lower_index_bound(&heap_obj_id, &Bitvector::from_u64(0).into());
    state
        .memory
        .set_upper_index_bound(&heap_obj_id, &Bitvector::from_u64(7).into());

    let pointer = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_i64(-1).into()).into();
    assert!(state.pointer_contains_out_of_bounds_target(&pointer, &global_data));
    let pointer = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(0).into()).into();
    assert!(!state.pointer_contains_out_of_bounds_target(&pointer, &global_data));
    let pointer = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(7).into()).into();
    assert!(!state.pointer_contains_out_of_bounds_target(&pointer, &global_data));
    let pointer = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(8).into()).into();
    assert!(state.pointer_contains_out_of_bounds_target(&pointer, &global_data));

    let address = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(0).into()).into();
    state.set_register(&Variable::mock("RAX", 8), address);
    let load_def = Def::load(
        "tid",
        Variable::mock("RBX", 8),
        Expression::Var(Variable::mock("RAX", 8)),
    );
    assert!(!state.contains_out_of_bounds_mem_access(&load_def.term, &global_data));

    let address = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(0).into()).into();
    state.set_register(&Variable::mock("RAX", 8), address);
    assert!(!state.contains_out_of_bounds_mem_access(&load_def.term, &global_data));
    let address = PointerDomain::new(heap_obj_id.clone(), Bitvector::from_u64(1).into()).into();
    state.set_register(&Variable::mock("RAX", 8), address);
    assert!(state.contains_out_of_bounds_mem_access(&load_def.term, &global_data));
    let address = PointerDomain::new(state.stack_id.clone(), Bitvector::from_u64(8).into()).into();
    state.set_register(&Variable::mock("RAX", 8), address);
    assert!(!state.contains_out_of_bounds_mem_access(&load_def.term, &global_data));
}
