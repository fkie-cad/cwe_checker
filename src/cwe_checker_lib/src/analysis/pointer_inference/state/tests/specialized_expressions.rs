use super::*;

/// Test expression specialization except for binary operations.
#[test]
fn specialize_by_expression_results() {
    let mut base_state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    base_state.set_register(
        &variable!("RAX:8"),
        IntervalDomain::new(bitvec!("5:8"), bitvec!("10:8")).into(),
    );

    // Expr = Var(RAX)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(&expr!("RAX:8"), bitvec!("7:8").into());
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("7:8").into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(&expr!("RAX:8"), bitvec!("-20:8").into());
    assert!(x.is_err());

    let mut state = base_state.clone();
    let abstract_id = AbstractIdentifier::new(
        Tid::new("heap_obj"),
        AbstractLocation::from_var(&variable!("RAX:8")).unwrap(),
    );
    state.set_register(
        &variable!("RAX:8"),
        Data::from_target(abstract_id.clone(), IntervalDomain::mock(0, 50)),
    );
    let x = state.specialize_by_expression_result(
        &expr!("RAX:8"),
        Data::from_target(abstract_id.clone(), IntervalDomain::mock(20, 70)),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        Data::from_target(abstract_id, IntervalDomain::mock(20, 50))
    );

    // Expr = Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(&expr!("-20:8"), bitvec!("-20:8").into());
    assert!(x.is_ok());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(&expr!("5:8"), bitvec!("-20:8").into());
    assert!(x.is_err());

    // Expr = -Var(RAX)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr!("RAX:8").un_op(UnOpType::Int2Comp),
        bitvec!("-7:8").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("7:8").into()
    );

    // Expr = IntSExt(Var(EAX))
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let eax_register = variable!("EAX:4");
    state.set_register(
        &eax_register,
        IntervalDomain::new(bitvec!("-7:4"), bitvec!("-5:4")).into(),
    );
    let x = state.specialize_by_expression_result(
        &expr!("EAX:4").cast(CastOpType::IntSExt),
        bitvec!("-7:8").into(),
    );
    assert!(x.is_ok());
    assert_eq!(state.get_register(&eax_register), bitvec!("-7:4").into());

    // Expr = Subpiece(Var(RAX))
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let rax_register = variable!("RAX:8");
    let x = state.specialize_by_expression_result(
        &Expression::Var(rax_register.clone()).subpiece(ByteSize::new(0), ByteSize::new(1)),
        bitvec!("5:1").into(),
    );
    assert!(x.is_ok());
    assert!(state.get_register(&rax_register).is_top());
    state.set_register(&rax_register, IntervalDomain::mock(3, 10).into());
    let x = state.specialize_by_expression_result(
        &Expression::Var(rax_register.clone()).subpiece(ByteSize::new(0), ByteSize::new(1)),
        bitvec!("5:1").into(),
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
    let base_state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());

    // Expr = RAX + Const
    let mut state = base_state.clone();
    let x = state
        .specialize_by_expression_result(&expr!("RAX:8 + 20:8"), IntervalDomain::mock(5, 7).into());
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(-15, -13).into()
    );

    // Expr = RAX - Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(&expr!("RAX:8 - 20:8"), bitvec!("5:8").into());
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("25:8").into()
    );

    // Expr = RAX xor Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntXOr, expr!("3:8")),
        bitvec!("-1:8").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("-4:8").into()
    );

    // Expr = (RAX or RBX == 0)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntOr, expr!("RBX:8")),
        bitvec!("0:8").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("0:8").into()
    );
    assert_eq!(
        state.get_register(&variable!("RBX:8")),
        bitvec!("0:8").into()
    );
    // Expr = (RAX or 0 == Const)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntOr, expr!("0:8")),
        bitvec!("42:8").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("42:8").into()
    );

    // Expr = (FLAG1 bool_and FLAG2 == 1)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("FLAG1:1"), BinOpType::BoolAnd, expr!("FLAG2:1")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("FLAG1:1")),
        bitvec!("1:1").into()
    );
    assert_eq!(
        state.get_register(&variable!("FLAG2:1")),
        bitvec!("1:1").into()
    );
    // Expr = (FLAG bool_and 1 = Const)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("1:1"), BinOpType::BoolAnd, expr!("FLAG:1")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("FLAG:1")),
        bitvec!("0:1").into()
    );
}

/// Test expression specialization for comparison operations `==` and `!=`.
#[test]
fn specialize_by_equality_comparison() {
    let mut base_state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    base_state.set_register(&variable!("RAX:8"), IntervalDomain::mock(0, 50).into());

    // Expr = RAX == Const
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("23:8"), BinOpType::IntEqual, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("23:8").into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("23:8"), BinOpType::IntNotEqual, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("23:8").into()
    );

    // Expr = RAX != Const
    let mut state = base_state.clone();
    state.set_register(&variable!("RAX:8"), bitvec!("23:8").into());
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("23:8"), BinOpType::IntNotEqual, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("100:8"), BinOpType::IntEqual, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 0, 50, Some(99)).into()
    );
}

/// Test expression specialization for signed comparison operations `<` and `<=`.
#[test]
fn specialize_by_signed_comparison_op() {
    let mut base_state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let interval = IntervalDomain::mock(5, 10);
    base_state.set_register(&variable!("RAX:8"), interval.into());

    // Expr = RAX < Const (signed)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("7:8"), BinOpType::IntSLess, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(8, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("15:8"), BinOpType::IntSLess, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 5, 10, Some(15)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(
            expr!("RAX:8"),
            BinOpType::IntSLess,
            Expression::Const(Bitvector::signed_min_value(ByteSize::new(8).into())),
        ),
        bitvec!("1:1").into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntSLess, expr!("7:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(7, 10).into()
    );

    // Expr = RAX <= Const (signed)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("7:8"), BinOpType::IntSLessEqual, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(7, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("15:8"), BinOpType::IntSLessEqual, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 5, 10, Some(14)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(
            expr!("RAX:8"),
            BinOpType::IntSLessEqual,
            Expression::Const(Bitvector::signed_min_value(ByteSize::new(8).into())),
        ),
        bitvec!("1:1").into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntSLessEqual, expr!("7:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(8, 10).into()
    );
}

/// Test expression specialization for unsigned comparison operations `<` and `<=`.
#[test]
fn specialize_by_unsigned_comparison_op() {
    let mut base_state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let interval = IntervalDomain::mock(-5, 10);
    base_state.set_register(&variable!("RAX:8"), interval.into());

    // Expr = RAX < Const (unsigned)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("7:8"), BinOpType::IntLess, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(-5, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("15:8"), BinOpType::IntLess, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 0, 10, Some(15)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntLess, expr!("0:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_err());
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntLess, expr!("-20:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(Some(-20), -5, -1, None).into()
    );

    // Expr = RAX <= Const (unsigned)
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("7:8"), BinOpType::IntLessEqual, expr!("RAX:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock(-5, 10).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("15:8"), BinOpType::IntLessEqual, expr!("RAX:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(None, 0, 10, Some(14)).into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntLessEqual, expr!("0:8")),
        bitvec!("1:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        bitvec!("0:8").into()
    );
    let mut state = base_state.clone();
    let x = state.specialize_by_expression_result(
        &expr_bi_op(expr!("RAX:8"), BinOpType::IntLessEqual, expr!("-20:8")),
        bitvec!("0:1").into(),
    );
    assert!(x.is_ok());
    assert_eq!(
        state.get_register(&variable!("RAX:8")),
        IntervalDomain::mock_with_bounds(Some(-19), -5, -1, None).into()
    );
}

#[test]
fn specialize_pointer_comparison() {
    let mut state = State::new(&variable!("RSP:8"), Tid::new("func_tid"), BTreeSet::new());
    let interval = IntervalDomain::mock(-5, 10);
    state.set_register(
        &variable!("RAX:8"),
        Data::from_target(new_id("func_tid", "RSP"), interval.into()),
    );
    let interval = IntervalDomain::mock(20, 20);
    state.set_register(
        &variable!("RBX:8"),
        Data::from_target(new_id("func_tid", "RSP"), interval.into()),
    );
    let expression = expr_bi_op(expr!("RAX:8"), BinOpType::IntEqual, expr!("RBX:8"));
    assert!(state
        .clone()
        .specialize_by_expression_result(&expression, bitvec!("1:1").into())
        .is_err());
    let specialized_interval = IntervalDomain::mock_with_bounds(None, -5, 10, Some(19));
    let specialized_pointer =
        Data::from_target(new_id("func_tid", "RSP"), specialized_interval.into());
    assert!(state
        .specialize_by_expression_result(&expression, bitvec!("0:1").into())
        .is_ok());
    assert_eq!(state.get_register(&variable!("RAX:8")), specialized_pointer);
}
