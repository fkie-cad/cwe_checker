use super::*;

fn bv(value: i64) -> BitvectorDomain {
    BitvectorDomain::Value(Bitvector::from_i64(value))
}

fn new_id(name: String) -> AbstractIdentifier {
    AbstractIdentifier::new(Tid::new("time0"), AbstractLocation::Register(name, 64))
}

fn register(name: &str) -> Variable {
    Variable {
        name: name.into(),
        type_: crate::bil::variable::Type::Immediate(64),
        is_temp: false,
    }
}

fn reg_add(name: &str, value: i64) -> Expression {
    Expression::BinOp {
        op: BinOpType::PLUS,
        lhs: Box::new(Expression::Var(register(name))),
        rhs: Box::new(Expression::Const(Bitvector::from_i64(value))),
    }
}

fn reg_sub(name: &str, value: i64) -> Expression {
    Expression::BinOp {
        op: BinOpType::MINUS,
        lhs: Box::new(Expression::Var(register(name))),
        rhs: Box::new(Expression::Const(Bitvector::from_i64(value))),
    }
}

fn store_exp(address: Expression, value: Expression) -> Expression {
    let mem_var = Variable {
        name: "mem".into(),
        type_: crate::bil::variable::Type::Memory {
            addr_size: 64,
            elem_size: 64,
        },
        is_temp: false,
    };
    Expression::Store {
        memory: Box::new(Expression::Var(mem_var)),
        address: Box::new(address),
        value: Box::new(value),
        endian: Endianness::LittleEndian,
        size: 64,
    }
}

fn load_exp(address: Expression) -> Expression {
    let mem_var = Variable {
        name: "mem".into(),
        type_: crate::bil::variable::Type::Memory {
            addr_size: 64,
            elem_size: 64,
        },
        is_temp: false,
    };
    Expression::Load {
        memory: Box::new(Expression::Var(mem_var)),
        address: Box::new(address),
        endian: Endianness::LittleEndian,
        size: 64,
    }
}

#[test]
fn state() {
    use crate::analysis::pointer_inference::object::*;
    use crate::bil::Expression::*;
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("RSP".into());
    let stack_addr = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(8)));
    state
        .store_value(&stack_addr, &Data::Value(bv(42)))
        .unwrap();
    state.register.insert(register("RSP"), stack_addr.clone());
    let load_expr = Load {
        memory: Box::new(Var(register("RSP"))), // This is wrong, but the memory var is not checked at the moment (since we have only the one for RAM)
        address: Box::new(Var(register("RSP"))),
        endian: Endianness::LittleEndian,
        size: 64 as BitSize,
    };
    assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(42)));

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
    assert_eq!(merged_state.eval(&load_expr).unwrap(), Data::new_top(64));

    // Test pointer adjustment on reads
    state
        .memory
        .add_abstract_object(new_id("caller".into()), bv(0), ObjectType::Stack, 64);
    state.caller_stack_ids.insert(new_id("caller".into()));
    state
        .store_value(&stack_addr, &Data::Value(bv(15)))
        .unwrap();
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("caller".into()), bv(8))),
                64
            )
            .unwrap(),
        Data::Value(bv(15))
    );
    assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(15)));

    // Test replace_abstract_id
    let pointer = Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16)));
    state.register.insert(register("RSP"), pointer.clone());
    state.store_value(&pointer, &Data::Value(bv(7))).unwrap();
    assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(7)));
    state.replace_abstract_id(&stack_id, &new_id("callee".into()), &bv(-8));
    assert_eq!(state.eval(&load_expr).unwrap(), Data::Value(bv(7)));
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("callee".into()), bv(-8))),
                64
            )
            .unwrap(),
        Data::Value(bv(7))
    );
    assert_eq!(
        state
            .memory
            .get_value(
                &Data::Pointer(PointerDomain::new(new_id("callee".into()), bv(-16))),
                64
            )
            .unwrap(),
        Data::new_top(64)
    );

    state
        .memory
        .add_abstract_object(new_id("heap_obj".into()), bv(0), ObjectType::Heap, 64);
    assert_eq!(state.memory.get_num_objects(), 3);
    state.remove_unreferenced_objects();
    assert_eq!(state.memory.get_num_objects(), 2);
}

#[test]
fn handle_store() {
    use crate::bil::Expression::*;
    let mut state = State::new(&register("RSP"), Tid::new("time0"));
    let stack_id = new_id("RSP".into());
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
        .handle_store_exp(&store_exp(reg_add("RSP", 8), Const(Bitvector::from_i64(1))))
        .unwrap();
    state
        .handle_store_exp(&store_exp(reg_sub("RSP", 8), Const(Bitvector::from_i64(2))))
        .unwrap();
    state
        .handle_store_exp(&store_exp(
            reg_add("RSP", -16),
            Const(Bitvector::from_i64(3)),
        ))
        .unwrap();
    state
        .handle_register_assign(&register("RSP"), &reg_sub("RSP", 4))
        .unwrap();

    assert_eq!(
        state.eval(&load_exp(reg_add("RSP", 12))).unwrap(),
        bv(1).into()
    );
    assert_eq!(
        state.eval(&load_exp(reg_sub("RSP", 4))).unwrap(),
        bv(2).into()
    );
    assert_eq!(
        state.eval(&load_exp(reg_add("RSP", -12))).unwrap(),
        bv(3).into()
    );
}
