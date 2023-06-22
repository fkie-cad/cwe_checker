use super::super::ValueDomain;
use super::*;
use crate::analysis::pointer_inference::object::*;
use crate::{bitvec, def, expr, variable};

mod specialized_expressions;

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(bitvec!(format!("{}:8", value)))
}

fn new_id(time: &str, register: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(time),
        AbstractLocation::Register(variable!(format!("{}:8", register))),
    )
}
fn expr_bi_op(lhs: Expression, op: BinOpType, rhs: Expression) -> Expression {
    Expression::BinOp {
        lhs: Box::new(lhs),
        op: op,
        rhs: Box::new(rhs),
    }
}

#[test]
fn state() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&variable!("RSP:8"), Tid::new("time0"), BTreeSet::new());
    let stack_id = new_id("time0", "RSP");
    let stack_addr = Data::from_target(stack_id.clone(), bv(8));
    state
        .store_value(&stack_addr, &bv(42).into(), &global_memory)
        .unwrap();
    state
        .register
        .insert(variable!("RSP:8"), stack_addr.clone());
    assert_eq!(
        state
            .load_value(&expr!("RSP:8"), ByteSize::new(8), &global_memory)
            .unwrap(),
        bv(42).into()
    );

    let mut other_state = State::new(&variable!("RSP:8"), Tid::new("time0"), BTreeSet::new());
    state.register.insert(variable!("RAX:8"), bv(42).into());
    other_state
        .register
        .insert(variable!("RSP:8"), stack_addr.clone());
    other_state
        .register
        .insert(variable!("RAX:8"), bv(42).into());
    other_state
        .register
        .insert(variable!("RBX:8"), bv(35).into());
    let merged_state = state.merge(&other_state);
    assert_eq!(merged_state.register[&variable!("RAX:8")], bv(42).into());
    assert_eq!(
        merged_state
            .get_register(&variable!("RBX:8"))
            .get_absolute_value()
            .unwrap(),
        &bv(35).into()
    );
    assert!(merged_state
        .get_register(&variable!("RBX:8"))
        .contains_top());
    assert!(merged_state
        .load_value(&expr!("RSP:8"), ByteSize::new(8), &global_memory)
        .unwrap()
        .contains_top());

    state.memory.add_abstract_object(
        new_id("heap_time", "heap_obj"),
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    assert_eq!(state.memory.get_num_objects(), 3);
    state.remove_unreferenced_objects();
    assert_eq!(state.memory.get_num_objects(), 2);
}

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
fn clear_parameters_on_the_stack_on_extern_calls() {
    let global_memory = RuntimeMemoryImage::mock();
    let mut state = State::new(&variable!("RSP:8"), Tid::new("time0"), BTreeSet::new());
    state.register.insert(
        variable!("RSP:8"),
        Data::from_target(new_id("time0", "RSP"), bv(-20)),
    );
    // write something onto the stack
    state
        .handle_store(&expr!("RSP:8 + 8:8"), &expr!("42:8"), &global_memory)
        .unwrap();
    // create an extern symbol which uses the value on the stack as a parameter
    let stack_param = Arg::Stack {
        address: expr!("RSP:8 + 8:8"),
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
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let stack_id = new_id("func_tid", "RSP");
    let heap_id = new_id("heap_obj", "RAX");
    let stack_address: Data = Data::from_target(stack_id.clone(), bitvec!("-8:8").into());
    let heap_address: Data = Data::from_target(heap_id.clone(), bitvec!("0:8").into());
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
        &bitvec!("42:8").into(),
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

/// Test that value specialization does not introduce unintended widening hints.
/// This is a regression test for cases where pointer comparisons introduced two-sided bounds
/// (resulting in two-sided widenings) instead of one-sided bounds.
#[test]
fn test_widening_hints_after_pointer_specialization() {
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    state.set_register(
        &variable!("RAX:8"),
        Data::from_target(new_id("func_tid", "RSP"), bitvec!("10:8").into()),
    );
    state.set_register(
        &variable!("RBX:8"),
        Data::from_target(new_id("func_tid", "RSP"), bitvec!("10:8").into()),
    );

    let neq_expression = expr_bi_op(expr!("5:8"), BinOpType::IntNotEqual, expr!("RAX:8 - RBX:8"));
    state
        .specialize_by_expression_result(&neq_expression, bitvec!("1:1").into())
        .unwrap();
    state
        .specialize_by_expression_result(&neq_expression, bitvec!("1:1").into())
        .unwrap();

    let offset_with_upper_bound: IntervalDomain = bitvec!("10:8").into();
    let offset_with_upper_bound = offset_with_upper_bound
        .add_signed_less_equal_bound(&bitvec!("14:8"))
        .unwrap();
    let expected_val = Data::from_target(new_id("func_tid", "RSP"), offset_with_upper_bound);
    assert_eq!(state.get_register(&variable!("RAX:8")), expected_val);

    let offset_with_lower_bound: IntervalDomain = bitvec!("10:8").into();
    let offset_with_lower_bound = offset_with_lower_bound
        .add_signed_greater_equal_bound(&Bitvector::from_i64(6))
        .unwrap();
    let expected_val = Data::from_target(new_id("func_tid", "RSP"), offset_with_lower_bound);
    assert_eq!(state.get_register(&variable!("RBX:8")), expected_val);
}

#[test]
fn test_check_def_for_null_dereferences() {
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let var_rax = variable!("RAX:8");
    let def = def![format!("load_def: RBX:8 := Load from {}", var_rax)];

    state.set_register(&var_rax, bitvec!("0:8").into());
    assert!(state.check_def_for_null_dereferences(&def).is_err());

    state.set_register(&var_rax, bitvec!("12345:8").into());
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

    let mut address = state.get_register(&variable!("RSP:8"));
    address.set_contains_top_flag();
    address.set_absolute_value(Some(IntervalDomain::mock(0, 0xffff)));
    state.set_register(&var_rax, address);
    assert_eq!(state.check_def_for_null_dereferences(&def).ok(), Some(true));
}

#[test]
fn from_fn_sig() {
    let fn_sig = FunctionSignature::mock_x64();
    let state = State::from_fn_sig(&fn_sig, &variable!("RSP:8"), Tid::new("func"));

    assert_eq!(state.memory.get_num_objects(), 3);
    assert_eq!(
        *state.memory.get_object(&new_id("func", "RSI")).unwrap(),
        AbstractObject::new(None, ByteSize::new(8))
    );
    assert_eq!(
        state.get_register(&variable!("RSP:8")),
        Data::from_target(new_id("func", "RSP"), bv(0).into())
    );
    assert_eq!(
        state.get_register(&variable!("RDI:8")),
        Data::from_target(new_id("func", "RDI"), bv(0).into())
    );
    assert_eq!(
        state.get_register(&variable!("RSI:8")),
        Data::from_target(new_id("func", "RSI"), bv(0).into())
    );
}

#[test]
fn add_param_object_from_callee() {
    let global_memory = RuntimeMemoryImage::empty(true);
    let mut generic_state = State::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new());
    generic_state
        .write_to_address(&expr!("RSP:8 + -8:8"), &bv(1).into(), &global_memory)
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
        .load_value(&expr!("RSP:8 + -8:8"), ByteSize::new(8), &global_memory)
        .unwrap();
    assert_eq!(value.get_absolute_value().unwrap(), &bv(1).into());
    assert!(value.contains_top());
    let value = state
        .load_value(&expr!("RSP:8 + -16:8"), ByteSize::new(8), &global_memory)
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
        .load_value(&expr!("RSP:8 + -16:8"), ByteSize::new(8), &global_memory)
        .unwrap();
    assert_eq!(value.get_absolute_value().unwrap(), &bv(2).into());
    assert!(value.contains_top());
}
