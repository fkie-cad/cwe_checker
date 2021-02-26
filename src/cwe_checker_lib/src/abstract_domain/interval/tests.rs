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
    let val = IntervalDomain::mock_i8_with_bounds(Some(-20), -10, -5, None);
    let extended_val = val.cast(CastOpType::IntZExt, ByteSize::new(8));
    assert_eq!(
        extended_val,
        IntervalDomain::mock_with_bounds(Some(236), 246, 251, Some(255))
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
