use crate::intermediate_representation::*;
use crate::prelude::*;

/// An interval of values with a fixed byte size.
///
/// The interval bounds are interpreted as signed integers,
/// i.e. `self.start` is not allowed to be greater than `self.end`
/// as signed integers.
#[derive(Serialize, Deserialize, Debug, Eq, Hash, Clone)]
pub struct Interval {
    /// The start of the interval. The bound is included in the represented interval. 
    pub start: Bitvector,
    /// The end of the interval. The bound is included in the represented interval.
    pub end: Bitvector,
}

impl PartialEq for Interval {
    fn eq(&self, other: &Interval) -> bool {
        // The `Top` value has more than one correct representation.
        (self.is_top() && other.is_top()) || (self.start == other.start && self.end == other.end)
    }
}

impl Interval {
    /// Construct a new interval.
    ///
    /// Both `start` and `end` of the interval are inclusive,
    /// i.e. contained in the represented interval.
    pub fn new(start: Bitvector, end: Bitvector) -> Interval {
        assert_eq!(start.width(), end.width());
        Interval { start, end }
    }

    /// Construct a new unconstrained interval.
    pub fn new_top(bytesize: ByteSize) -> Interval {
        Interval {
            start: Bitvector::signed_min_value(bytesize.into()),
            end: Bitvector::signed_max_value(bytesize.into()),
        }
    }

    /// Returns true if all values representable by bitvectors of the corresponding length are contained in the interval.
    pub fn is_top(&self) -> bool {
        (self.start.clone() - &Bitvector::one(self.start.width())) == self.end
    }

    /// Get the size in bytes of values contained in the interval.
    pub fn bytesize(&self) -> ByteSize {
        self.start.width().into()
    }

    /// Merge two intervals interpreting both as intervals of signed integers.
    pub fn signed_merge(&self, other: &Interval) -> Interval {
        if self.start.checked_sgt(&self.end).unwrap()
            || other.start.checked_sgt(&other.end).unwrap()
        {
            // One of the intervals wraps around
            return Interval::new_top(self.bytesize());
        }
        let start = signed_min(&self.start, &other.start);
        let end = signed_max(&self.end, &other.end);
        Interval { start, end }
    }

    /// Return the number of contained values of the interval.
    pub fn length(&self) -> Bitvector {
        self.end.clone() - &self.start + &Bitvector::one(self.start.width())
    }

    /// Compute the interval represented if the byte size of the value is zero-extended.
    pub fn zero_extend(self, width: ByteSize) -> Interval {
        assert!(self.bytesize() <= width);
        if self.bytesize() == width {
            return self;
        }
        if self.start.sign_bit().to_bool() == self.end.sign_bit().to_bool() {
            // Both start and end have the same sign
            Interval {
                start: self.start.into_zero_extend(width).unwrap(),
                end: self.end.into_zero_extend(width).unwrap(),
            }
        } else {
            // The interval either contains both -1 and 0 or wraps around
            Interval {
                start: Bitvector::zero(width.into()),
                end: Bitvector::unsigned_max_value(self.end.width())
                    .into_zero_extend(width)
                    .unwrap(),
            }
        }
    }

    /// Take a subpiece of the bitvectors.
    ///
    /// The function only tries to be exact if the interval contains exact one value
    /// or if the `low_byte` is zero.
    pub fn subpiece(self, low_byte: ByteSize, size: ByteSize) -> Self {
        if self.start == self.end {
            self.start.subpiece(low_byte, size).into()
        } else if low_byte == ByteSize::new(0) {
            let new_min = Bitvector::signed_min_value(size.into())
                .into_sign_extend(self.bytesize())
                .unwrap();
            let new_max = Bitvector::signed_max_value(size.into())
                .into_sign_extend(self.bytesize())
                .unwrap();
            if self.start.checked_sge(&new_min).unwrap() && self.end.checked_sle(&new_max).unwrap()
            {
                Interval {
                    start: self.start.into_truncate(size).unwrap(),
                    end: self.end.into_truncate(size).unwrap(),
                }
            } else {
                Interval::new_top(size)
            }
        } else {
            Interval::new_top(size)
        }
    }

    /// Take the 2's complement of values in the interval.
    pub fn int_2_comp(self) -> Self {
        if self
            .start
            .checked_sgt(&Bitvector::signed_min_value(self.bytesize().into()))
            .unwrap()
        {
            Interval {
                start: -self.end,
                end: -self.start,
            }
        } else {
            Interval::new_top(self.bytesize())
        }
    }

    /// Compute the bitwise negation of values in the interval.
    /// Only exact if there is exactly one value in the interval.
    pub fn bitwise_not(self) -> Self {
        if self.start == self.end {
            self.start.into_bitnot().into()
        } else {
            Interval::new_top(self.bytesize())
        }
    }

    /// Compute the interval of possible results
    /// if one adds a value from `self` to a value from `rhs`.
    pub fn add(&self, rhs: &Interval) -> Interval {
        if self.start.signed_add_overflow_check(&rhs.start)
            || self.end.signed_add_overflow_check(&rhs.end)
        {
            Interval::new_top(self.bytesize())
        } else {
            Interval {
                start: self.start.clone().into_checked_add(&rhs.start).unwrap(),
                end: self.end.clone().into_checked_add(&rhs.end).unwrap(),
            }
        }
    }


    /// Compute the interval of possible results
    /// if one subtracts a value in `rhs` from a value in `self`.
    pub fn sub(&self, rhs: &Interval) -> Interval {
        if self.start.signed_sub_overflow_check(&rhs.end)
            || self.end.signed_sub_overflow_check(&rhs.start)
        {
            Interval::new_top(self.bytesize())
        } else {
            Interval {
                start: self.start.clone().into_checked_sub(&rhs.end).unwrap(),
                end: self.end.clone().into_checked_sub(&rhs.start).unwrap(),
            }
        }
    }

    /// Compute the interval of possible results
    /// if one multiplies a value in `self` with a value in `rhs`.
    pub fn signed_mul(&self, rhs: &Interval) -> Interval {
        let val1 = self.start.signed_mult_with_overflow_flag(&rhs.start);
        let val2 = self.start.signed_mult_with_overflow_flag(&rhs.end);
        let val3 = self.end.signed_mult_with_overflow_flag(&rhs.start);
        let val4 = self.end.signed_mult_with_overflow_flag(&rhs.end);
        if val1.1 || val2.1 || val3.1 || val4.1 {
            // (signed) overflow during multiplication
            return Interval::new_top(self.bytesize());
        }
        let min = signed_min(&val1.0, &signed_min(&val2.0, &signed_min(&val3.0, &val4.0)));
        let max = signed_max(&val1.0, &signed_max(&val2.0, &signed_max(&val3.0, &val4.0)));
        Interval {
            start: min,
            end: max,
        }
    }
}

impl From<Bitvector> for Interval {
    /// Create an interval that only contains the given bitvector.
    fn from(bitvec: Bitvector) -> Self {
        Interval {
            start: bitvec.clone(),
            end: bitvec,
        }
    }
}

fn signed_min(v1: &Bitvector, v2: &Bitvector) -> Bitvector {
    if v1.checked_sle(v2).unwrap() {
        v1.clone()
    } else {
        v2.clone()
    }
}

fn signed_max(v1: &Bitvector, v2: &Bitvector) -> Bitvector {
    if v1.checked_sge(v2).unwrap() {
        v1.clone()
    } else {
        v2.clone()
    }
}