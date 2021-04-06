use super::*;

impl IntervalDomain {
    /// Return a new interval domain of 8-byte integers.
    pub fn mock(start: i64, end: i64) -> IntervalDomain {
        IntervalDomain::new(Bitvector::from_i64(start), Bitvector::from_i64(end))
    }

    /// Return a new interval domain of 1-byte integers.
    pub fn mock_i8(start: i8, end: i8) -> IntervalDomain {
        IntervalDomain::new(Bitvector::from_i8(start), Bitvector::from_i8(end))
    }

    pub fn mock_with_bounds(
        lower_bound: Option<i64>,
        start: i64,
        end: i64,
        upper_bound: Option<i64>,
    ) -> IntervalDomain {
        let mut domain = IntervalDomain::mock(start, end);
        domain.update_widening_lower_bound(&lower_bound.map(|b| Bitvector::from_i64(b)));
        domain.update_widening_upper_bound(&upper_bound.map(|b| Bitvector::from_i64(b)));
        domain
    }

    pub fn mock_i8_with_bounds(
        lower_bound: Option<i8>,
        start: i8,
        end: i8,
        upper_bound: Option<i8>,
    ) -> IntervalDomain {
        let mut domain = IntervalDomain::mock_i8(start, end);
        domain.update_widening_lower_bound(&lower_bound.map(|b| Bitvector::from_i8(b)));
        domain.update_widening_upper_bound(&upper_bound.map(|b| Bitvector::from_i8(b)));
        domain
    }
}

#[test]
fn signed_merge() {
    // simple widening examples
    let a = IntervalDomain::mock_with_bounds(None, 0, 3, Some(10));
    let b = IntervalDomain::mock_with_bounds(None, 2, 5, None);
    assert_eq!(
        a.merge(&b),
        IntervalDomain::mock_with_bounds(None, 0, 10, None)
    );
    let a = IntervalDomain::mock_with_bounds(Some(-3), 1, 1, None);
    let b = IntervalDomain::mock_with_bounds(None, 2, 2, Some(5));
    assert_eq!(
        a.merge(&b),
        IntervalDomain::mock_with_bounds(Some(-3), 1, 2, Some(5))
    );
    let a = IntervalDomain::mock_with_bounds(Some(-3), 1, 1, None);
    let b = IntervalDomain::mock_with_bounds(None, 3, 3, Some(5));
    assert_eq!(
        a.merge(&b),
        IntervalDomain::mock_with_bounds(None, -3, 5, None)
    );
    let a = IntervalDomain::mock_with_bounds(None, 1, 5, None);
    let b = IntervalDomain::mock_with_bounds(None, -1, -1, Some(5));
    assert_eq!(a.merge(&b), IntervalDomain::new_top(ByteSize::new(8)));
    let a = IntervalDomain::mock_with_bounds(None, 1, 5, None);
    let b = IntervalDomain::mock_with_bounds(None, 3, 3, Some(10));
    assert_eq!(
        a.merge(&b),
        IntervalDomain::mock_with_bounds(None, 1, 5, Some(10))
    );
    let a = IntervalDomain::mock_with_bounds(None, 20, -5, None);
    let b = IntervalDomain::mock_with_bounds(None, 0, 0, Some(50));
    assert_eq!(a.merge(&a), IntervalDomain::new_top(ByteSize::new(8))); // Interval wraps and is thus merged to `Top`, even though a = a
    assert_eq!(a.merge(&b), IntervalDomain::new_top(ByteSize::new(8)));

    // Widening process corresponding to a very simple loop counter variable
    let mut var = IntervalDomain::mock(0, 0);
    let update = IntervalDomain::mock_with_bounds(None, 1, 1, Some(99));
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::mock_with_bounds(None, 0, 1, Some(99)));
    let update = IntervalDomain::mock_with_bounds(None, 1, 2, Some(99));
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::mock_with_bounds(None, 0, 99, None));
    let update = IntervalDomain::mock_with_bounds(None, 1, 99, None);
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::mock_with_bounds(None, 0, 99, None));

    // Widening process corresponding to a loop counter variable with bound in the wrong direction
    let mut var = IntervalDomain::mock(0, 0);
    let update = IntervalDomain::mock_with_bounds(Some(-3), 1, 1, None);
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::mock_with_bounds(Some(-3), 0, 1, None));
    let update = IntervalDomain::mock_with_bounds(Some(-3), 1, 2, None);
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::mock_with_bounds(None, -3, 2, None));
    let update = IntervalDomain::mock_with_bounds(Some(-3), -2, 3, None);
    var = var.merge(&update);
    assert_eq!(var, IntervalDomain::new_top(ByteSize::new(8)));
}

#[test]
fn cast_zero_and_signed_extend() {
    // Zero extend
    let val = IntervalDomain::mock_i8_with_bounds(Some(1), 3, 5, Some(30));
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(1), 3, 5, Some(30))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-10), 0, 5, Some(30));
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(None, 0, 5, Some(30))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-15), -10, 5, None);
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(None, 0, 255, None)
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-14), -9, -5, Some(-2));
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(242), 247, 251, Some(254))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-20), -10, -5, Some(3));
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(236), 246, 251, Some(255))
    );

    // Sign extend
    let val = IntervalDomain::mock_i8_with_bounds(Some(1), 3, 5, Some(30));
    let extended_val = val.cast(CastOpType::IntSExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(1), 3, 5, Some(30))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-10), 0, 5, Some(30));
    let extended_val = val.cast(CastOpType::IntSExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(-10), 0, 5, Some(30))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-15), -10, 127, None);
    let extended_val = val.cast(CastOpType::IntSExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(-15), -10, 127, None)
    );
    let val = IntervalDomain::mock_i8_with_bounds(None, -10, -5, None);
    let extended_val = val.cast(CastOpType::IntSExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(-128), -10, -5, Some(127))
    );
    let val = IntervalDomain::mock_i8_with_bounds(Some(-20), -10, -5, Some(3));
    let extended_val = val.cast(CastOpType::IntSExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(-20), -10, -5, Some(3))
    );
}

#[test]
fn subpiece() {
    let val = IntervalDomain::mock_with_bounds(None, -3, 5, Some(10));
    let subpieced_val = val.subpiece(ByteSize::new(0), ByteSize::new(1));
    assert_eq!(
        subpieced_val,
        IntervalDomain::mock_i8_with_bounds(None, -3, 5, None)
    );
    let val = IntervalDomain::mock_with_bounds(Some(-30), 2, 5, Some(10));
    let subpieced_val = val.subpiece(ByteSize::new(0), ByteSize::new(1));
    assert_eq!(
        subpieced_val,
        IntervalDomain::mock_i8_with_bounds(Some(-30), 2, 5, Some(10))
    );
    let val = IntervalDomain::mock_with_bounds(Some(-500), 2, 5, Some(10));
    let subpieced_val = val.subpiece(ByteSize::new(0), ByteSize::new(1));
    assert_eq!(
        subpieced_val,
        IntervalDomain::mock_i8_with_bounds(None, 2, 5, None)
    );
    let val = IntervalDomain::mock_with_bounds(Some(-30), 2, 567, Some(777));
    let subpieced_val = val.subpiece(ByteSize::new(0), ByteSize::new(1));
    assert_eq!(subpieced_val, IntervalDomain::new_top(ByteSize::new(1)));
    let val = IntervalDomain::mock_with_bounds(Some(-30), 2, 3, Some(777));
    let subpieced_val = val.subpiece(ByteSize::new(1), ByteSize::new(1));
    assert_eq!(subpieced_val, IntervalDomain::new_top(ByteSize::new(1)));
    let val = IntervalDomain::mock_with_bounds(Some(-30), 512, 512, Some(777));
    let subpieced_val = val.subpiece(ByteSize::new(1), ByteSize::new(1));
    assert_eq!(
        subpieced_val,
        IntervalDomain::mock_i8_with_bounds(None, 2, 2, None)
    );
}

#[test]
fn un_op() {
    // Int2Comp
    let mut val = IntervalDomain::mock_with_bounds(None, -3, 5, Some(10));
    val = val.un_op(UnOpType::Int2Comp);
    assert_eq!(
        val,
        IntervalDomain::mock_with_bounds(Some(-10), -5, 3, None)
    );
    let mut val = IntervalDomain::mock_i8_with_bounds(Some(-128), -3, 5, Some(127));
    val = val.un_op(UnOpType::Int2Comp);
    assert_eq!(
        val,
        IntervalDomain::mock_i8_with_bounds(Some(-127), -5, 3, None)
    );
    // IntNegate
    let mut val = IntervalDomain::mock_with_bounds(None, -3, 5, Some(10));
    val = val.un_op(UnOpType::IntNegate);
    assert_eq!(val, IntervalDomain::new_top(ByteSize::new(8)));
    let mut val = IntervalDomain::mock_with_bounds(None, -4, -4, Some(10));
    val = val.un_op(UnOpType::IntNegate);
    assert_eq!(val, IntervalDomain::mock(3, 3));
}

#[test]
fn add() {
    let lhs = IntervalDomain::mock_with_bounds(None, 3, 7, Some(10));
    let rhs = IntervalDomain::mock_with_bounds(Some(-20), -3, 0, Some(10));
    let result = lhs.bin_op(BinOpType::IntAdd, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_with_bounds(None, 0, 7, Some(20))
    );
    let lhs = IntervalDomain::mock_i8_with_bounds(Some(-121), -120, -120, Some(10));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(-10), -9, 0, Some(10));
    let result = lhs.bin_op(BinOpType::IntAdd, &rhs);
    assert_eq!(result, IntervalDomain::new_top(ByteSize::new(1)));
    let lhs = IntervalDomain::mock_i8_with_bounds(Some(-100), 2, 4, Some(100));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(-50), 10, 20, Some(50));
    let result = lhs.bin_op(BinOpType::IntAdd, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_i8_with_bounds(None, 12, 24, None)
    );
}

#[test]
fn sub() {
    let lhs = IntervalDomain::mock_with_bounds(None, 3, 7, Some(10));
    let rhs = IntervalDomain::mock_with_bounds(Some(-20), -3, 0, Some(10));
    let result = lhs.bin_op(BinOpType::IntSub, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_with_bounds(None, 3, 10, Some(30))
    );
    let lhs = IntervalDomain::mock_i8_with_bounds(Some(-121), -120, -120, Some(10));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(-10), -9, 9, Some(10));
    let result = lhs.bin_op(BinOpType::IntSub, &rhs);
    assert_eq!(result, IntervalDomain::new_top(ByteSize::new(1)));
    let lhs = IntervalDomain::mock_i8_with_bounds(Some(-100), 2, 4, Some(100));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(-50), 10, 20, Some(50));
    let result = lhs.bin_op(BinOpType::IntSub, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_i8_with_bounds(None, -18, -6, None)
    );
}

#[test]
fn multiplication() {
    let lhs = IntervalDomain::mock_with_bounds(None, 3, 7, Some(10));
    let rhs = IntervalDomain::mock_with_bounds(Some(-20), -3, 0, Some(10));
    let result = lhs.bin_op(BinOpType::IntMult, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_with_bounds(Some(-200), -21, 0, Some(100))
    );
    let lhs = IntervalDomain::mock_with_bounds(Some(-4), -3, 1, Some(2));
    let rhs = IntervalDomain::mock_with_bounds(Some(-6), -5, 7, Some(8));
    let result = lhs.bin_op(BinOpType::IntMult, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_with_bounds(Some(-32), -21, 15, Some(16))
    );
    let lhs = IntervalDomain::mock_i8_with_bounds(None, 3, 7, Some(50));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(-30), -3, 0, Some(50));
    let result = lhs.bin_op(BinOpType::IntMult, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_i8_with_bounds(None, -21, 0, None)
    );
}

#[test]
fn shift_left() {
    let lhs = IntervalDomain::mock_i8_with_bounds(None, 3, 3, Some(50));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(1), 2, 3, Some(4));
    let result = lhs.bin_op(BinOpType::IntLeft, &rhs);
    assert_eq!(result, IntervalDomain::new_top(ByteSize::new(1)));
    let lhs = IntervalDomain::mock_i8_with_bounds(None, 3, 4, Some(5));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(1), 2, 2, Some(4));
    let result = lhs.bin_op(BinOpType::IntLeft, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_i8_with_bounds(None, 12, 16, None)
    );
    let lhs = IntervalDomain::mock_i8_with_bounds(Some(2), 3, 4, Some(64));
    let rhs = IntervalDomain::mock_i8_with_bounds(Some(0), 1, 1, Some(4));
    let result = lhs.bin_op(BinOpType::IntLeft, &rhs);
    assert_eq!(
        result,
        IntervalDomain::mock_i8_with_bounds(None, 6, 8, None)
    );
    let lhs = IntervalDomain::mock_with_bounds(Some(2), 3, 4, Some(64));
    let rhs = IntervalDomain::mock_i8_with_bounds(None, 127, 127, None);
    let result = lhs.bin_op(BinOpType::IntLeft, &rhs);
    assert_eq!(result, IntervalDomain::mock(0, 0));
}
