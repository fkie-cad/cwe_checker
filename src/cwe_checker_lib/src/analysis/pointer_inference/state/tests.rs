use super::super::ValueDomain;
use super::*;
use crate::analysis::pointer_inference::object::*;
use crate::utils::binary::RuntimeMemoryImage;
use Expression::*;

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(time: &str, register: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(time),
        AbstractLocation::Register(Variable::mock(register, ByteSize::new(8))),
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
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("time0", "RSP");
    let stack_addr = Data::from_target(stack_id.clone(), bv(8));
    state
        .store_value(&stack_addr, &bv(42).into(), &global_memory)
        .unwrap();
    state.register.insert(register("RSP"), stack_addr.clone());
    assert_eq!(
        state
            .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(42).into()
    );

    let mut other_state = State::new(&register("RSP"), Tid::new("time0"));
    state.register.insert(register("RAX"), bv(42).into());
    other_state
        .register
        .insert(register("RSP"), stack_addr.clone());
    other_state.register.insert(register("RAX"), bv(42).into());
    other_state.register.insert(register("RBX"), bv(35).into());
    let merged_state = state.merge(&other_state);
    assert_eq!(merged_state.register[&register("RAX")], bv(42).into());
    assert_eq!(
        merged_state
            .get_register(&register("RBX"))
            .get_absolute_value()
            .unwrap(),
        &bv(35).into()
    );
    assert!(merged_state.get_register(&register("RBX")).contains_top());
    assert!(merged_state
        .load_value(&Var(register("RSP")), ByteSize::new(8), &global_memory)
        .unwrap()
        .contains_top());

    state.memory.add_abstract_object(
        new_id("heap_time", "heap_obj"),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    assert_eq!(state.memory.get_num_objects(), 2);
    state.remove_unreferenced_objects();
    assert_eq!(state.memory.get_num_objects(), 1);
}

#[test]
fn handle_store() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("time0", "RSP");
    assert_eq!(
        state.eval(&Var(register("RSP"))),
        Data::from_target(stack_id.clone(), bv(0))
    );

    state.handle_register_assign(&register("RSP"), &reg_sub("RSP", 32));
    assert_eq!(
        state.eval(&Var(register("RSP"))),
        Data::from_target(stack_id.clone(), bv(-32))
    );
    state.handle_register_assign(&register("RSP"), &reg_add("RSP", -8));
    assert_eq!(
        state.eval(&Var(register("RSP"))),
        Data::from_target(stack_id.clone(), bv(-40))
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
fn clear_parameters_on_the_stack_on_extern_calls() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    state.register.insert(
        register("RSP"),
        Data::from_target(new_id("time0", "RSP"), bv(-20)),
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
        address: reg_add("RSP", 8),
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
    let pointer = Data::from_target(new_id("time0", "RSP"), bv(-12));
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)),
        bv(42).into()
    );
    // clear stack parameter
    state
        .clear_stack_parameter(&extern_symbol, &global_memory)
        .unwrap();
    // check the value after
    assert_eq!(
        state.memory.get_value(&pointer, ByteSize::new(8)),
        Data::new_top(ByteSize::new(8))
    );
}

#[test]
fn reachable_ids_under_and_overapproximation() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let stack_id = new_id("func_tid", "RSP");
    let heap_id = new_id("heap_obj", "RAX");
    let stack_address: Data = Data::from_target(stack_id.clone(), Bitvector::from_i64(-8).into());
    let heap_address: Data = Data::from_target(heap_id.clone(), Bitvector::from_i64(0).into());
    // Add the heap object to the state, so that it can be recursively searched.
    state
        .memory
        .add_abstract_object(heap_id.clone(), ByteSize::new(8), Some(ObjectType::Heap));

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
        &Data::from_target(stack_id.clone(), ValueDomain::new_top(ByteSize::new(8))),
        &Bitvector::from_i64(42).into(),
        &global_memory,
    );
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
        Bitvector::from_u32(0xb3b2b1b0).into() // note that we read in little-endian byte order
    );
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::new_top(ByteSize::new(4)),
            &global_memory
        )
        .is_err());

    // global writeable address
    let address_expr = Expression::Const(Bitvector::from_u64(0x2000));
    assert_eq!(
        state
            .load_value(&address_expr, ByteSize::new(4), &global_memory)
            .unwrap(),
        DataDomain::new_top(ByteSize::new(4))
    );
    assert!(state
        .write_to_address(
            &address_expr,
            &DataDomain::new_top(ByteSize::new(4)),
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
            &DataDomain::new_top(ByteSize::new(4)),
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
        Data::from_target(abstract_id.clone(), IntervalDomain::mock(0, 50)),
    );
    let x = state.specialize_by_expression_result(
        &Expression::var("RAX", 8),
        Data::from_target(abstract_id.clone(), IntervalDomain::mock(20, 70)),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&register("RAX")),
        Data::from_target(abstract_id, IntervalDomain::mock(20, 50))
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
fn specialize_pointer_comparison() {
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let interval = IntervalDomain::mock(-5, 10);
    state.set_register(
        &register("RAX"),
        Data::from_target(new_id("func_tid", "RSP"), interval.into()),
    );
    let interval = IntervalDomain::mock(20, 20);
    state.set_register(
        &register("RBX"),
        Data::from_target(new_id("func_tid", "RSP"), interval.into()),
    );
    let expression = Expression::BinOp {
        op: BinOpType::IntEqual,
        lhs: Box::new(Expression::Var(register("RAX"))),
        rhs: Box::new(Expression::Var(register("RBX"))),
    };
    assert!(state
        .clone()
        .specialize_by_expression_result(&expression, Bitvector::from_i8(1).into())
        .is_err());
    let specialized_interval = IntervalDomain::mock_with_bounds(None, -5, 10, Some(19));
    let specialized_pointer =
        Data::from_target(new_id("func_tid", "RSP"), specialized_interval.into());
    assert!(state
        .specialize_by_expression_result(&expression, Bitvector::from_i8(0).into())
        .is_ok());
    assert_eq!(state.get_register(&register("RAX")), specialized_pointer);
}

#[test]
fn test_check_def_for_null_dereferences() {
    let mut state = State::new(&register("RSP"), Tid::new("func_tid"));
    let var_rax = Variable::mock("RAX", 8);
    let def = Def::load(
        "load_def",
        Variable::mock("RBX", 8),
        Expression::Var(var_rax.clone()),
    );
    state.set_register(&var_rax, Bitvector::from_i64(0).into());
    assert!(state.check_def_for_null_dereferences(&def).is_err());

    state.set_register(&var_rax, Bitvector::from_i64(12345).into());
    assert_eq!(
        state.check_def_for_null_dereferences(&def).ok(),
        Some(false)
    );

    state.set_register(&var_rax, IntervalDomain::mock(-2000, 5).into());
    assert_eq!(state.check_def_for_null_dereferences(&def).ok(), Some(true));
    assert_eq!(
        state.get_register(&var_rax),
        IntervalDomain::mock(-2000, -1024).into()
    );

    let mut address = state.get_register(&register("RSP"));
    address.set_contains_top_flag();
    address.set_absolute_value(Some(IntervalDomain::mock(0, 0xffff)));
    state.set_register(&var_rax, address);
    assert_eq!(state.check_def_for_null_dereferences(&def).ok(), Some(true));
}

#[test]
fn from_fn_sig() {
    let fn_sig = FunctionSignature::mock_x64();
    let state = State::from_fn_sig(&fn_sig, &Variable::mock("RSP", 8), Tid::new("func"));

    assert_eq!(state.memory.get_num_objects(), 2);
    assert_eq!(
        *state.memory.get_object(&new_id("func", "RSI")).unwrap(),
        AbstractObject::new(None, ByteSize::new(8))
    );
    assert_eq!(
        state.get_register(&Variable::mock("RSP", 8)),
        Data::from_target(new_id("func", "RSP"), bv(0).into())
    );
    assert_eq!(
        state.get_register(&Variable::mock("RDI", 8)),
        Data::from_target(new_id("func", "RDI"), bv(0).into())
    );
    assert_eq!(
        state.get_register(&Variable::mock("RSI", 8)),
        Data::from_target(new_id("func", "RSI"), bv(0).into())
    );
}

#[test]
fn add_param_object_from_callee() {
    let global_memory = RuntimeMemoryImage::empty(true);
    let mut generic_state = State::new(&Variable::mock("RSP", 8), Tid::new("func"));
    generic_state
        .write_to_address(
            &Expression::Var(Variable::mock("RSP", 8)).plus_const(-8),
            &bv(1).into(),
            &global_memory,
        )
        .unwrap();
    let mut param_object = AbstractObject::new(None, ByteSize::new(8));
    param_object.set_value(bv(2).into(), &bv(0).into()).unwrap();
    let mut param_value = Data::from_target(new_id("func", "RSP"), bv(-16).into());

    // Testcase 1: param object is unique
    let mut state = generic_state.clone();
    state
        .add_param_object_from_callee(param_object.clone(), &param_value)
        .unwrap();
    let value = state
        .load_value(
            &Expression::Var(Variable::mock("RSP", 8)).plus_const(-8),
            ByteSize::new(8),
            &global_memory,
        )
        .unwrap();
    assert_eq!(value.get_absolute_value().unwrap(), &bv(1).into());
    assert!(value.contains_top());
    let value = state
        .load_value(
            &Expression::Var(Variable::mock("RSP", 8)).plus_const(-16),
            ByteSize::new(8),
            &global_memory,
        )
        .unwrap();
    assert_eq!(value.get_absolute_value().unwrap(), &bv(2).into());
    assert!(!value.contains_top());

    // Testcase 2: param object is not unique
    let mut state = generic_state.clone();
    param_value.set_contains_top_flag();
    state
        .add_param_object_from_callee(param_object.clone(), &param_value)
        .unwrap();
    let value = state
        .load_value(
            &Expression::Var(Variable::mock("RSP", 8)).plus_const(-16),
            ByteSize::new(8),
            &global_memory,
        )
        .unwrap();
    assert_eq!(value.get_absolute_value().unwrap(), &bv(2).into());
    assert!(value.contains_top());
}
