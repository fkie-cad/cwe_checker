use super::*;

impl Expression {
    /// Substitute cases, where a binary operation can be simplified because the left and right operand are identical.
    fn substitute_binop_for_lhs_equal_rhs(&mut self) {
        use BinOpType::*;
        use Expression::*;
        if let BinOp { op, lhs, rhs } = self {
            if lhs == rhs {
                match op {
                    BoolAnd | BoolOr | IntAnd | IntOr => {
                        // This is an identity operation
                        *self = (**lhs).clone();
                    }
                    BoolXOr | IntXOr => {
                        // `a xor a` always equals zero.
                        *self = Expression::Const(Bitvector::zero(lhs.bytesize().into()));
                    }
                    IntEqual | IntLessEqual | IntSLessEqual => {
                        *self = Expression::Const(Bitvector::one(ByteSize::new(1).into()));
                    }
                    IntNotEqual | IntLess | IntSLess => {
                        *self = Expression::Const(Bitvector::zero(ByteSize::new(1).into()));
                    }
                    _ => (),
                }
            }
        }
    }

    /// Substitute `AND`, `OR` and `XOR` operations where one operand is a constant.
    fn substitute_and_xor_or_with_constant(&mut self) {
        use BinOpType::*;
        use Expression::*;
        if let BinOp { op, lhs, rhs } = self {
            match (&**lhs, op, &**rhs) {
                (Const(bitvec), op, other) | (other, op, Const(bitvec))
                    if bitvec.is_zero() && matches!(op, IntOr | IntXOr | BoolOr | BoolXOr) =>
                {
                    // `a or 0 = a` and `a xor 0 = a`
                    *self = other.clone();
                }
                (Const(bitvec), op, other) | (other, op, Const(bitvec))
                    if bitvec.clone().into_bitnot().is_zero() && matches!(op, IntAnd | BoolAnd) =>
                {
                    // `a and -1 = a` since all bits of -1 are 1.
                    *self = other.clone()
                }
                (Const(bitvec), BoolAnd, _other) | (_other, BoolAnd, Const(bitvec))
                    if bitvec.is_zero() =>
                {
                    // `a and 0 = 0` for booleans
                    *self = Const(bitvec.clone());
                }
                (Const(bitvec), BoolAnd, other) | (other, BoolAnd, Const(bitvec))
                    if bitvec.is_one() =>
                {
                    // `a and 1 = a` for booleans
                    *self = other.clone();
                }
                (Const(bitvec), BoolOr, _other) | (_other, BoolOr, Const(bitvec))
                    if bitvec.is_one() =>
                {
                    // `a or 1 = 1` for booleans
                    *self = Const(bitvec.clone());
                }
                (Const(bitvec), BoolXOr, other) | (other, BoolXOr, Const(bitvec))
                    if bitvec.is_one() =>
                {
                    // `a xor 1 = ¬a` for booleans
                    *self = UnOp {
                        op: UnOpType::BoolNegate,
                        arg: Box::new(other.clone()),
                    };
                }
                _ => (),
            }
        }
    }

    /// Simplify some comparison operations.
    ///
    /// For example, `a == b || a < b` can be simplified to `a <= b`.
    fn substitute_equivalent_comparison_ops(&mut self) {
        use BinOpType::*;
        use Expression::*;
        if let BinOp { op, lhs, rhs } = self {
            match (&**lhs, op, &**rhs) {
                (
                    Const(bitvec),
                    op,
                    Expression::BinOp {
                        lhs: inner_lhs,
                        op: IntSub,
                        rhs: inner_rhs,
                    },
                )
                | (
                    Expression::BinOp {
                        lhs: inner_lhs,
                        op: IntSub,
                        rhs: inner_rhs,
                    },
                    op,
                    Const(bitvec),
                ) if (bitvec.is_zero() || bitvec.is_one())
                    && matches!(op, IntEqual | IntNotEqual) =>
                {
                    // `0 == x - y` is equivalent to `x == y`
                    let new_op = match (op, bitvec.is_zero()) {
                        (IntEqual, true) | (IntNotEqual, false) => IntEqual,
                        (IntEqual, false) | (IntNotEqual, true) => IntNotEqual,
                        _ => unreachable!(),
                    };
                    *self = Expression::BinOp {
                        lhs: inner_lhs.clone(),
                        op: new_op,
                        rhs: inner_rhs.clone(),
                    }
                }
                (
                    Expression::BinOp {
                        lhs: less_left,
                        op: IntSLess,
                        rhs: less_right,
                    },
                    BoolOr,
                    Expression::BinOp {
                        lhs: equal_left,
                        op: IntEqual,
                        rhs: equal_right,
                    },
                )
                | (
                    Expression::BinOp {
                        lhs: equal_left,
                        op: IntEqual,
                        rhs: equal_right,
                    },
                    BoolOr,
                    Expression::BinOp {
                        lhs: less_left,
                        op: IntSLess,
                        rhs: less_right,
                    },
                ) if (less_left == equal_left && less_right == equal_right)
                    || (less_left == equal_right && less_right == equal_left) =>
                {
                    // `x < y or x == y` is equivalent to `x <= y `
                    *self = Expression::BinOp {
                        lhs: less_left.clone(),
                        op: IntSLessEqual,
                        rhs: less_right.clone(),
                    };
                }
                (
                    Expression::BinOp {
                        lhs: less_left,
                        op: IntLess,
                        rhs: less_right,
                    },
                    BoolOr,
                    Expression::BinOp {
                        lhs: equal_left,
                        op: IntEqual,
                        rhs: equal_right,
                    },
                )
                | (
                    Expression::BinOp {
                        lhs: equal_left,
                        op: IntEqual,
                        rhs: equal_right,
                    },
                    BoolOr,
                    Expression::BinOp {
                        lhs: less_left,
                        op: IntLess,
                        rhs: less_right,
                    },
                ) if (less_left == equal_left && less_right == equal_right)
                    || (less_left == equal_right && less_right == equal_left) =>
                {
                    // `x < y or x == y` is equivalent to `x <= y `
                    *self = Expression::BinOp {
                        lhs: less_left.clone(),
                        op: IntLessEqual,
                        rhs: less_right.clone(),
                    };
                }
                (
                    Expression::BinOp {
                        lhs: lessequal_left,
                        op: IntLessEqual,
                        rhs: lessequal_right,
                    },
                    BoolAnd,
                    Expression::BinOp {
                        lhs: notequal_left,
                        op: IntNotEqual,
                        rhs: notequal_right,
                    },
                )
                | (
                    Expression::BinOp {
                        lhs: notequal_left,
                        op: IntNotEqual,
                        rhs: notequal_right,
                    },
                    BoolAnd,
                    Expression::BinOp {
                        lhs: lessequal_left,
                        op: IntLessEqual,
                        rhs: lessequal_right,
                    },
                ) if (lessequal_left == notequal_left && lessequal_right == notequal_right)
                    || (lessequal_left == notequal_right && lessequal_right == notequal_left) =>
                {
                    // `x <= y and x != y` is equivalent to `x < y `
                    *self = Expression::BinOp {
                        lhs: lessequal_left.clone(),
                        op: IntLess,
                        rhs: lessequal_right.clone(),
                    };
                }
                (
                    Expression::BinOp {
                        lhs: lessequal_left,
                        op: IntSLessEqual,
                        rhs: lessequal_right,
                    },
                    BoolAnd,
                    Expression::BinOp {
                        lhs: notequal_left,
                        op: IntNotEqual,
                        rhs: notequal_right,
                    },
                )
                | (
                    Expression::BinOp {
                        lhs: notequal_left,
                        op: IntNotEqual,
                        rhs: notequal_right,
                    },
                    BoolAnd,
                    Expression::BinOp {
                        lhs: lessequal_left,
                        op: IntSLessEqual,
                        rhs: lessequal_right,
                    },
                ) if (lessequal_left == notequal_left && lessequal_right == notequal_right)
                    || (lessequal_left == notequal_right && lessequal_right == notequal_left) =>
                {
                    // `x <= y and x != y` is equivalent to `x < y `
                    *self = Expression::BinOp {
                        lhs: lessequal_left.clone(),
                        op: IntSLess,
                        rhs: lessequal_right.clone(),
                    };
                }
                _ => (),
            }
        }
    }

    /// Simplify arithmetic operations where intermediate results can be computed because some operands are constants.
    fn substitute_arithmetics_with_constants(&mut self) {
        use BinOpType::*;
        use Expression::*;
        if let BinOp { op, lhs, rhs } = self {
            match (&**lhs, op, &**rhs) {
                (Const(left), op, Const(right)) if matches!(op, IntSub | IntAdd) => {
                    // Compute the result of arithmetics with constants
                    *self = Const(
                        left.bin_op(*op, right)
                            .expect("Arithmetic operation with non-matching byte sizes."),
                    );
                }
                (
                    BinOp {
                        lhs: left,
                        op: IntSub,
                        rhs: middle,
                    },
                    IntSub,
                    Const(const_right),
                ) => {
                    if let Const(const_middle) = &**middle {
                        // `(x - const_1) - const_2 = x - (const_1 + const_2)`
                        *self = BinOp {
                            lhs: left.clone(),
                            op: IntSub,
                            rhs: Box::new(Const(const_middle.bin_op(IntAdd, const_right).unwrap())),
                        }
                    }
                }
                (
                    BinOp {
                        lhs: left,
                        op: IntAdd,
                        rhs: middle,
                    },
                    IntAdd,
                    Const(const_right),
                ) => {
                    if let Const(const_middle) = &**middle {
                        // `(x + const_1) + const_2 = x + (const_1 + const_2)`
                        *self = BinOp {
                            lhs: left.clone(),
                            op: IntAdd,
                            rhs: Box::new(Const(const_middle.bin_op(IntAdd, const_right).unwrap())),
                        }
                    } else if let Const(const_left) = &**left {
                        // `(const_1 + x) + const_2 = x + (const_1 + const_2)`
                        *self = BinOp {
                            lhs: middle.clone(),
                            op: IntAdd,
                            rhs: Box::new(Const(const_left.bin_op(IntAdd, const_right).unwrap())),
                        }
                    }
                }
                _ => (),
            }
        }
    }

    /// Substitute trivial BinOp-expressions with their results,
    /// e.g. substitute `a or a` with `a`.
    ///
    /// This function assumes that `self` is a `BinOp`
    /// and it does not substitute trivial expressions in the two input expressions of the `BinOp`.
    fn substitute_trivial_binops(&mut self) {
        self.substitute_binop_for_lhs_equal_rhs();
        self.substitute_and_xor_or_with_constant();
        self.substitute_equivalent_comparison_ops();
        self.substitute_arithmetics_with_constants();
    }

    /// Substitute some trivial expressions with their result.
    /// E.g. substitute `a XOR a` with zero or substitute `a OR a` with `a`.
    pub fn substitute_trivial_operations(&mut self) {
        use Expression::*;
        match self {
            Var(_) | Const(_) | Unknown { .. } => (),
            Subpiece {
                low_byte,
                size,
                arg,
            } => {
                arg.substitute_trivial_operations();
                if *low_byte == ByteSize::new(0) && *size == arg.bytesize() {
                    *self = (**arg).clone();
                } else {
                    match &**arg {
                        Expression::Cast {
                            arg: inner_arg,
                            op: CastOpType::IntZExt,
                            ..
                        }
                        | Expression::Cast {
                            arg: inner_arg,
                            op: CastOpType::IntSExt,
                            ..
                        } if *low_byte == ByteSize::new(0) && *size == inner_arg.bytesize() => {
                            // The zero or sign extended part is thrown away by the subpiece ooperation.
                            *self = (**inner_arg).clone();
                        }
                        Expression::BinOp {
                            op: BinOpType::Piece,
                            lhs,
                            rhs,
                        } => {
                            // If the subpiece extracts exactly the `lhs` or the `rhs` of the piece operation,
                            // we can simplify to just `lhs` or `rhs`.
                            if *low_byte == rhs.bytesize() && *size == lhs.bytesize() {
                                *self = (**lhs).clone();
                            } else if *low_byte == ByteSize::new(0) && *size == rhs.bytesize() {
                                *self = (**rhs).clone();
                            }
                        }
                        Expression::Subpiece {
                            low_byte: inner_low_byte,
                            size: _,
                            arg: inner_arg,
                        } => {
                            // Subpiece of subpiece can be simplified to a single subpiece operation.
                            *self = Expression::Subpiece {
                                low_byte: *low_byte + *inner_low_byte,
                                size: *size,
                                arg: (*inner_arg).clone(),
                            }
                        }
                        _ => (),
                    }
                }
            }
            Cast { op, size, arg } => {
                arg.substitute_trivial_operations();
                if (*op == CastOpType::IntSExt || *op == CastOpType::IntZExt)
                    && *size == arg.bytesize()
                {
                    *self = (**arg).clone();
                } else if *op == CastOpType::IntSExt || *op == CastOpType::IntZExt {
                    match &**arg {
                        Expression::Cast {
                            op: inner_op,
                            size: _,
                            arg: inner_arg,
                        } if *op == *inner_op => {
                            // Merge two zero/sign-extension to one.
                            *self = Expression::Cast {
                                op: *op,
                                size: *size,
                                arg: inner_arg.clone(),
                            };
                        }
                        _ => (),
                    }
                }
            }
            UnOp { op, arg } => {
                arg.substitute_trivial_operations();
                match &**arg {
                    Expression::UnOp {
                        op: inner_op,
                        arg: inner_arg,
                    } if op == inner_op
                        && matches!(
                            op,
                            UnOpType::IntNegate | UnOpType::BoolNegate | UnOpType::Int2Comp
                        ) =>
                    {
                        *self = (**inner_arg).clone();
                    }
                    Expression::BinOp {
                        lhs: inner_lhs,
                        op: inner_op,
                        rhs: inner_rhs,
                    } if *op == UnOpType::BoolNegate
                        && matches!(
                            inner_op,
                            BinOpType::IntEqual
                                | BinOpType::IntNotEqual
                                | BinOpType::IntLess
                                | BinOpType::IntSLess
                                | BinOpType::IntLessEqual
                                | BinOpType::IntSLessEqual
                        ) =>
                    {
                        // `!( x < y)` is equivalent to ` y <= x`
                        let new_op = match inner_op {
                            BinOpType::IntEqual => BinOpType::IntNotEqual,
                            BinOpType::IntNotEqual => BinOpType::IntEqual,
                            BinOpType::IntLess => BinOpType::IntLessEqual,
                            BinOpType::IntSLess => BinOpType::IntSLessEqual,
                            BinOpType::IntLessEqual => BinOpType::IntLess,
                            BinOpType::IntSLessEqual => BinOpType::IntSLess,
                            _ => unreachable!(),
                        };
                        // Note that we have to swap the left hand side with the right hand side of the binary expression.
                        *self = Expression::BinOp {
                            lhs: inner_rhs.clone(),
                            op: new_op,
                            rhs: inner_lhs.clone(),
                        };
                    }
                    _ => (),
                }
            }
            BinOp { op: _, lhs, rhs } => {
                lhs.substitute_trivial_operations();
                rhs.substitute_trivial_operations();
                self.substitute_trivial_binops();
            }
        }
    }
}
