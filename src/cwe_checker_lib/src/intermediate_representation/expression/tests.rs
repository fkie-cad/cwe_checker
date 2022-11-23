use super::*;

#[test]
fn trivial_expression_substitution() {
    let rax_variable = Expression::Var(Variable::mock("RAX", 8));
    let rcx_variable = Expression::Var(Variable::mock("RCX", 8));
    let mut expr = Expression::BinOp {
        op: BinOpType::IntXOr,
        lhs: Box::new(rax_variable.clone()),
        rhs: Box::new(rax_variable.clone()),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::Const(Bitvector::zero(ByteSize::new(8).into()))
    );
    let mut expr = Expression::BinOp {
        op: BinOpType::IntOr,
        lhs: Box::new(rax_variable.clone()),
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(8).into()))),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, rax_variable);

    let sub_expr = Expression::BinOp {
        lhs: Box::new(rax_variable.clone()),
        op: BinOpType::IntSub,
        rhs: Box::new(rcx_variable.clone()),
    };
    let mut expr = Expression::BinOp {
        op: BinOpType::IntEqual,
        lhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
        rhs: Box::new(sub_expr.clone()),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntEqual,
            rhs: Box::new(rcx_variable.clone()),
        }
    );
    let mut expr = Expression::BinOp {
        op: BinOpType::IntNotEqual,
        lhs: Box::new(sub_expr.clone()),
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntNotEqual,
            rhs: Box::new(rcx_variable.clone()),
        }
    );
    // Test `x < y || x == y` substitutes to `x <= y`
    let mut expr = Expression::BinOp {
        lhs: Box::new(Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntLess,
            rhs: Box::new(rcx_variable.clone()),
        }),
        op: BinOpType::BoolOr,
        rhs: Box::new(Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntEqual,
            rhs: Box::new(rcx_variable.clone()),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(rcx_variable.clone()),
        }
    );
    // Test `x <= y && x != y` transforms to `x < y`
    let mut expr = Expression::BinOp {
        lhs: Box::new(Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntSLessEqual,
            rhs: Box::new(rcx_variable.clone()),
        }),
        op: BinOpType::BoolAnd,
        rhs: Box::new(Expression::BinOp {
            lhs: Box::new(rcx_variable.clone()),
            op: BinOpType::IntNotEqual,
            rhs: Box::new(rax_variable.clone()),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntSLess,
            rhs: Box::new(rcx_variable.clone()),
        }
    );

    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(Expression::Cast {
            op: CastOpType::IntSExt,
            size: ByteSize::new(8),
            arg: Box::new(Expression::Var(Variable::mock("EAX", 4))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, Expression::Var(Variable::mock("EAX", 4)));
    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(4),
        size: ByteSize::new(4),
        arg: Box::new(Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::Var(Variable::mock("EAX", 4))),
            rhs: Box::new(Expression::Var(Variable::mock("EBX", 4))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, Expression::Var(Variable::mock("EAX", 4)));
    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(2),
            size: ByteSize::new(6),
            arg: Box::new(Expression::Var(Variable::mock("RAX", 8))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::Subpiece {
            low_byte: ByteSize::new(2),
            size: ByteSize::new(4),
            arg: Box::new(Expression::Var(Variable::mock("RAX", 8))),
        }
    );

    let mut expr = Expression::UnOp {
        op: UnOpType::BoolNegate,
        arg: Box::new(Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntLess,
            rhs: Box::new(rcx_variable.clone()),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rcx_variable.clone()),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(rax_variable.clone()),
        }
    );
    // Test (x - const_1) - const_2 = x - (const_1 + const_2)
    let mut expr = Expression::BinOp {
        lhs: Box::new(Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntSub,
            rhs: Box::new(Expression::Const(Bitvector::from_i64(3))),
        }),
        op: BinOpType::IntSub,
        rhs: Box::new(Expression::Const(Bitvector::from_i64(4))),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(rax_variable.clone()),
            op: BinOpType::IntSub,
            rhs: Box::new(Expression::Const(Bitvector::from_i64(7)))
        }
    );
}

#[test]
fn test_complicated_a_less_than_b_substitution() {
    use BinOpType::*;
    use Expression::*;
    let sborrow_expr = BinOp {
        op: IntSBorrow,
        lhs: Box::new(Var(Variable::mock("RAX", 8))),
        rhs: Box::new(Var(Variable::mock("RBX", 8))),
    };
    let a_minus_b_less_zero_expr = BinOp {
        op: IntSLess,
        lhs: Box::new(BinOp {
            op: IntSub,
            lhs: Box::new(Var(Variable::mock("RAX", 8))),
            rhs: Box::new(Var(Variable::mock("RBX", 8))),
        }),
        rhs: Box::new(Const(Bitvector::from_u64(0))),
    };
    let mut expr = BinOp {
        op: IntNotEqual,
        lhs: Box::new(sborrow_expr),
        rhs: Box::new(a_minus_b_less_zero_expr),
    };
    expr.substitute_trivial_operations();
    let expected_expr = BinOp {
        op: IntSLess,
        lhs: Box::new(Var(Variable::mock("RAX", 8))),
        rhs: Box::new(Var(Variable::mock("RBX", 8))),
    };
    assert_eq!(expr, expected_expr);
}

#[test]
fn display() {
    let expr = Expression::const_from_i32(2);
    let mul = Expression::BinOp {
        op: BinOpType::IntMult,
        lhs: Box::new(Expression::Var(Variable::mock("RAX", 8))),
        rhs: Box::new(Expression::Var(Variable::mock("RBP", 8))),
    };
    let expr = expr.plus(mul);
    let expr = Expression::UnOp {
        op: UnOpType::IntNegate,
        arg: Box::new(expr),
    };
    let expr = expr
        .cast(CastOpType::IntSExt)
        .un_op(UnOpType::FloatCeil)
        .subpiece(ByteSize(0), ByteSize(20));

    assert_eq!(
        "(FloatCeil(IntSExt(IntNegate((0x2:i32 + RAX:64 * RBP:64)))))[0-19]",
        format!("{}", expr)
    );
}
