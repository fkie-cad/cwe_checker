use crate::intermediate_representation::*;
use crate::prelude::*;

/// An interval of values with a fixed byte size.
///
/// The interval bounds are interpreted as signed integers,
/// i.e. `self.start` is not allowed to be greater than `self.end`
/// as signed integers.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Interval {
    /// The start of the interval. The bound is included in the represented interval.
    pub start: Bitvector,
    /// The end of the interval. The bound is included in the represented interval.
    pub end: Bitvector,
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

    /// Compute the intersection of two intervals as intervals of signed integers.
    /// Return an error if the intersection is empty.
    pub fn signed_intersect(&self, other: &Interval) -> Result<Interval, Error> {
        let start = signed_max(&self.start, &other.start);
        let end = signed_min(&self.end, &other.end);
        if start.checked_sle(&end).unwrap() {
            Ok(Interval { start, end })
        } else {
            Err(anyhow!("Empty interval"))
        }
    }

    /// Return the number of contained values of the interval as an unsigned bitvector.
    /// If the interval is unconstrained, return zero
    /// (since the maximal number of elements is not representable in a bitvector of the same byte size).
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

    /// Truncate the bitvectors in the interval
    /// by removing the least significant bytes lower than the `low_byte` from them.
    pub fn subpiece_higher(self, low_byte: ByteSize) -> Self {
        Interval {
            start: self.start.subpiece(low_byte, self.bytesize() - low_byte),
            end: self.end.subpiece(low_byte, self.bytesize() - low_byte),
        }
    }

    /// Truncate the bitvectors in the interval to `size`,
    /// i.e. the most significant bytes (higher than `size`) are removed from all values.
    pub fn subpiece_lower(self, size: ByteSize) -> Self {
        let length = self.length();
        if !length.is_zero()
            && length
                .checked_ule(
                    &Bitvector::unsigned_max_value(size.into())
                        .into_zero_extend(self.bytesize())
                        .unwrap(),
                )
                .unwrap()
        {
            let start = self.start.into_truncate(size).unwrap();
            let end = self.end.into_truncate(size).unwrap();
            if start.checked_sle(&end).unwrap() {
                return Interval { start, end };
            }
        }
        Self::new_top(size)
    }

    /// Take a subpiece of the bitvectors.
    pub fn subpiece(mut self, low_byte: ByteSize, size: ByteSize) -> Self {
        if low_byte != ByteSize::new(0) {
            self = self.subpiece_higher(low_byte);
        }
        if self.bytesize() > size {
            self = self.subpiece_lower(size);
        }
        self
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
        if let (Some(start), Some(end)) = (
            self.start.signed_add_overflow_checked(&rhs.start),
            self.end.signed_add_overflow_checked(&rhs.end),
        ) {
            Interval { start, end }
        } else {
            Interval::new_top(self.bytesize())
        }
    }

    /// Compute the interval of possible results
    /// if one subtracts a value in `rhs` from a value in `self`.
    pub fn sub(&self, rhs: &Interval) -> Interval {
        if let (Some(start), Some(end)) = (
            self.start.signed_sub_overflow_checked(&rhs.end),
            self.end.signed_sub_overflow_checked(&rhs.start),
        ) {
            Interval { start, end }
        } else {
            Interval::new_top(self.bytesize())
        }
    }

    /// Compute the interval of possible results
    /// if one multiplies a value in `self` with a value in `rhs`.
    pub fn signed_mul(&self, rhs: &Interval) -> Interval {
        if self.bytesize().as_bit_length() > 64 {
            return Interval::new_top(self.bytesize());
        }
        let val1 = self
            .start
            .signed_mult_with_overflow_flag(&rhs.start)
            .unwrap();
        let val2 = self.start.signed_mult_with_overflow_flag(&rhs.end).unwrap();
        let val3 = self.end.signed_mult_with_overflow_flag(&rhs.start).unwrap();
        let val4 = self.end.signed_mult_with_overflow_flag(&rhs.end).unwrap();
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

    /// Return `true` if `bitvec` is contained in the interval.
    /// Panics if the interval and `bitvec` have different bytesizes.
    pub fn contains(&self, bitvec: &Bitvector) -> bool {
        self.start.checked_sle(bitvec).unwrap() && self.end.checked_sge(bitvec).unwrap()
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

/// Helper function returning the (signed) minimum of two bitvectors.
fn signed_min(v1: &Bitvector, v2: &Bitvector) -> Bitvector {
    if v1.checked_sle(v2).unwrap() {
        v1.clone()
    } else {
        v2.clone()
    }
}

/// Helper function returning the (signed) maximum of two bitvectors.
fn signed_max(v1: &Bitvector, v2: &Bitvector) -> Bitvector {
    if v1.checked_sge(v2).unwrap() {
        v1.clone()
    } else {
        v2.clone()
    }
}
