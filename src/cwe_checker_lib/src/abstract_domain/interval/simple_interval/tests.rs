use crate::bitvec;

use super::*;

impl Interval {
    pub fn mock(start: i64, end: i64) -> Interval {
        Interval::new(
            bitvec!(format!("{}:8", start)),
            bitvec!(format!("{}:8", end)),
            1,
        )
    }

    pub fn mock_i8(start: i8, end: i8) -> Interval {
        Interval::new(
            bitvec!(format!("{}:1", start)),
            bitvec!(format!("{}:1", end)),
            1,
        )
    }

    pub fn with_stride(mut self, stride: u64) -> Interval {
        self.stride = stride;
        self
    }
}

#[test]
fn signed_merge() {
    // Strides and Merge
    let a = Interval::mock(1, 13).with_stride(6);
    let b = Interval::mock(4, 10).with_stride(3);
    assert_eq!(a.signed_merge(&b), Interval::mock(1, 13).with_stride(3));

    let a = Interval::mock(1, 13).with_stride(6);
    let b = Interval::mock(3, 9).with_stride(3);
    assert_eq!(a.signed_merge(&b), Interval::mock(1, 13).with_stride(1));

    let a = Interval::mock(0, 24).with_stride(12);
    let b = Interval::mock(2, 42).with_stride(4);
    assert_eq!(a.signed_merge(&b), Interval::mock(0, 42).with_stride(2));
}

#[test]
fn adjust_start_or_end_to_value_in_stride() {
    let mut val = Interval::mock(-3, 10).with_stride(7);
    val.adjust_start_to_value_in_stride();
    assert_eq!(val, Interval::mock(3, 10).with_stride(7));
    let mut val = Interval::mock(-3, 10).with_stride(7);
    val.adjust_end_to_value_in_stride();
    assert_eq!(val, Interval::mock(-3, 4).with_stride(7));

    let mut val = Interval::mock(-3, 2).with_stride(7);
    val.adjust_start_to_value_in_stride();
    assert_eq!(val, Interval::mock(2, 2).with_stride(0));
    let mut val = Interval::mock(-3, 2).with_stride(7);
    val.adjust_end_to_value_in_stride();
    assert_eq!(val, Interval::mock(-3, -3).with_stride(0));
}

#[test]
fn adjust_to_stride_and_remainder() {
    let val = Interval::mock(-17, 23).with_stride(5);
    assert_eq!(
        val.adjust_to_stride_and_remainder(4, 2).unwrap(),
        Interval::mock(-14, 22).with_stride(4)
    );
    let val = Interval::mock(7, 24);
    assert!(val.adjust_to_stride_and_remainder(50, 5).is_err());
    let val = Interval::mock(5, 5).with_stride(1);
    assert_eq!(
        val.adjust_to_stride_and_remainder(1, 0).unwrap(),
        Interval::mock(5, 5)
    );
}

#[test]
fn zero_extend() {
    // Interval with only non-negative values
    let val = Interval::mock_i8(11, 51).with_stride(10);
    assert_eq!(
        val.zero_extend(ByteSize::new(8)),
        Interval::mock(11, 51).with_stride(10)
    );
    // Interval with only negative values
    let val = Interval::mock_i8(-50, -10).with_stride(10);
    assert_eq!(
        val.zero_extend(ByteSize::new(8)),
        Interval::mock(206, 246).with_stride(10)
    );
    // Interval with both positive and negative values
    let val = Interval::mock_i8(-3, 21).with_stride(12);
    assert_eq!(val.clone().zero_extend(ByteSize::new(1)), val);
    assert_eq!(
        val.zero_extend(ByteSize::new(8)),
        Interval::mock(1, 253).with_stride(4)
    );
}

#[test]
fn subpiece_higher() {
    let val = Interval::mock(3, 21).with_stride(6);
    assert_eq!(
        val.subpiece_higher(ByteSize::new(7)),
        Interval::from(bitvec!("0:1"))
    )
}

#[test]
fn subpiece_lower() {
    let val = Interval::mock(-15, 25).with_stride(10);
    assert_eq!(
        val.subpiece_lower(ByteSize::new(1)),
        Interval::mock_i8(-15, 25).with_stride(10)
    );
    let val = Interval::mock(-256, 25).with_stride(10);
    assert_eq!(
        val.subpiece_lower(ByteSize::new(1)),
        Interval::new_top(ByteSize::new(1))
    );
}

#[test]
fn piece() {
    let left = Interval::mock_i8(1, 4).with_stride(3);
    let right = Interval::mock_i8(-2, 2).with_stride(2);
    assert_eq!(
        left.piece(&right),
        Interval {
            start: bitvec!("256:2"),
            end: bitvec!("1278:2"),
            stride: 2,
        }
    );
    let left = Interval::mock_i8(1, 4).with_stride(3);
    let right = Interval::mock_i8(3, 15).with_stride(6);
    assert_eq!(
        left.piece(&right),
        Interval {
            start: bitvec!("259:2"),
            end: bitvec!("1039:2"),
            stride: 2,
        }
    );
}

#[test]
fn add_and_sub() {
    let left = Interval::mock(3, 15).with_stride(12);
    let right = Interval::mock(-2, 18).with_stride(10);
    assert_eq!(left.add(&right), Interval::mock(1, 33).with_stride(2));
    assert_eq!(left.sub(&right), Interval::mock(-15, 17).with_stride(2));
}

#[test]
fn contains() {
    let interval = Interval::mock(2, 10).with_stride(4);
    let elem = bitvec!("4:8");
    assert!(!interval.contains(&elem));
    let elem = bitvec!("6:8");
    assert!(interval.contains(&elem));
    let elem = bitvec!("14:8");
    assert!(!interval.contains(&elem));
}

#[test]
fn test_extended_gcd() {
    assert_eq!(extended_gcd(48, 21), (3, -3, 7));
}

#[test]
fn test_compute_intersection_residue_class() {
    let left = Interval::mock(21, 421).with_stride(20);
    let right = Interval::mock(11, 191).with_stride(15);
    assert_eq!(
        compute_intersection_residue_class(&left, &right).unwrap(),
        Some((60, 41))
    );

    let left = Interval::mock(21, 421).with_stride(20);
    let right = Interval::mock(14, 194).with_stride(15);
    assert_eq!(
        compute_intersection_residue_class(&left, &right).unwrap(),
        None
    );

    let left = Interval::mock(0, 2 << 60).with_stride(2 << 60);
    let right = Interval::mock(2, (2 << 60) + 1).with_stride((2 << 60) - 1);
    assert!(compute_intersection_residue_class(&left, &right).is_err());

    let left = Interval::mock(3, 3);
    let right = Interval::mock(0, 15).with_stride(3);
    assert_eq!(
        compute_intersection_residue_class(&left, &right).unwrap(),
        Some((3, 0))
    );

    let left = Interval::mock(3, 23).with_stride(5);
    let right = Interval::mock(8, 8);
    assert_eq!(
        compute_intersection_residue_class(&left, &right).unwrap(),
        Some((5, 3))
    );

    let left = Interval::mock(3, 3);
    let right = Interval::mock(0, 15).with_stride(5);
    assert_eq!(
        compute_intersection_residue_class(&left, &right).unwrap(),
        None
    );
}

#[test]
fn signed_intersect() {
    let left = Interval::mock(21, 421).with_stride(20);
    let right = Interval::mock(11, 191).with_stride(15);
    assert_eq!(
        left.signed_intersect(&right).unwrap(),
        Interval::mock(41, 161).with_stride(60)
    );

    let left = Interval::mock(21, 421).with_stride(20);
    let right = Interval::mock(14, 194).with_stride(15);
    assert!(left.signed_intersect(&right).is_err());

    let left = Interval::mock(0, 2 << 60).with_stride(2 << 60);
    let right = Interval::mock(2, (2 << 60) + 1).with_stride((2 << 60) - 1);
    assert!(left.signed_intersect(&right).is_err());
}
