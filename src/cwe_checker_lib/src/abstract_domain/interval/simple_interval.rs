use crate::intermediate_representation::*;
use crate::prelude::*;
use gcd::Gcd;

/// A strided interval of values with a fixed byte size.
///
/// The interval bounds are interpreted as signed integers,
/// i.e. `self.start` is not allowed to be greater than `self.end`
/// as signed integers.
///
/// The values represented by the interval are `start, start + stride, start + 2*stride, ... , end`.
/// The following invariants have to hold for a correct interval instance:
/// - `end - start % stride == 0`
/// - if `start == end`, then the stride should always be set to zero.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Interval {
    /// The start of the interval. The bound is included in the represented interval.
    pub start: Bitvector,
    /// The end of the interval. The bound is included in the represented interval.
    pub end: Bitvector,
    /// The stride.
    pub stride: u64,
}

impl Interval {
    /// Construct a new interval.
    ///
    /// Both `start` and `end` of the interval are inclusive,
    /// i.e. contained in the represented interval.
    ///
    /// The function automatically rounds down `end` (if necessary)
    /// so that it is contained in the same residue class as the start value modulo the stride.
    /// If the stride is 0 then `end` will be set to `start`.
    pub fn new(start: Bitvector, end: Bitvector, stride: u64) -> Interval {
        assert_eq!(start.width(), end.width());
        let mut interval = Interval { start, end, stride };
        interval.adjust_end_to_value_in_stride();
        interval
    }

    /// Construct a new unconstrained interval.
    pub fn new_top(bytesize: ByteSize) -> Interval {
        Interval {
            start: Bitvector::signed_min_value(bytesize.into()),
            end: Bitvector::signed_max_value(bytesize.into()),
            stride: 1,
        }
    }

    /// Returns true if all values representable by bitvectors of the corresponding length are contained in the interval.
    pub fn is_top(&self) -> bool {
        (self.start.clone() - &Bitvector::one(self.start.width())) == self.end && self.stride == 1
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
        let start_diff = if self.start.checked_sgt(&other.start).unwrap() {
            self.start.clone() - &other.start
        } else {
            other.start.clone() - &self.start
        };
        let stride = if let Ok(start_diff) = start_diff.try_to_u64() {
            self.stride.gcd(other.stride).gcd(start_diff)
        } else {
            1
        };
        Interval { start, end, stride }
    }

    /// Compute the intersection of two intervals as intervals of signed integers.
    /// Return an error if the intersection is empty.
    pub fn signed_intersect(&self, other: &Interval) -> Result<Interval, Error> {
        let start = signed_max(&self.start, &other.start);
        let end = signed_min(&self.end, &other.end);

        if self.stride == 0 && other.stride == 0 {
            if start == end {
                return Ok(Interval {
                    start,
                    end,
                    stride: 0,
                });
            } else {
                return Err(anyhow!("Empty interval"));
            }
        }
        if self.start.bytesize() > ByteSize::new(8) {
            // We ignore the stride for bytesizes larger than 8 bytes
            let stride = !(start == end) as u64; // 0 if start == end, else 1
            if start.checked_sle(&end).unwrap() {
                return Ok(Interval { start, end, stride });
            } else {
                return Err(anyhow!("Empty interval"));
            }
        }
        if let Some((stride, remainder)) = compute_intersection_residue_class(self, other)? {
            Interval { start, end, stride }.adjust_to_stride_and_remainder(stride, remainder)
        } else {
            Err(anyhow!("Empty interval"))
        }
    }

    /// If `self.start == self.end` set the stride to 0 and to 1 if `self.start < self.end`.
    fn set_stride_to_unknown(&mut self) {
        if self.start == self.end {
            self.stride = 0;
        } else {
            self.stride = 1;
        }
    }

    /// Round down `self.end` to the nearest value such that `self.end - self.start` is again divisible by the stride.
    /// If afterwards `self.start == self.end` holds then set the stride to 0.
    pub fn adjust_end_to_value_in_stride(&mut self) {
        if self.stride == 0 {
            self.end = self.start.clone();
            return;
        }
        if self.stride == 1 && self.start != self.end {
            return;
        }
        if let (Ok(start), Ok(end)) = (self.start.try_to_i64(), self.end.try_to_i64()) {
            let diff = (end - start) as u64 % self.stride;
            let diff = Bitvector::from_u64(diff).into_resize_unsigned(self.end.bytesize());
            self.end.checked_sub_assign(&diff).unwrap();
            if self.start == self.end {
                self.stride = 0;
            }
        } else {
            self.set_stride_to_unknown();
        }
    }

    /// Round up `self.start` to the nearest value such that `self.end - self.start` is again divisible by the stride.
    /// If afterwards `self.start == self.end` holds then set the stride to 0.
    pub fn adjust_start_to_value_in_stride(&mut self) {
        if self.stride == 0 {
            self.start = self.end.clone();
            return;
        }
        if self.stride == 1 && self.start != self.end {
            return;
        }
        if let (Ok(start), Ok(end)) = (self.start.try_to_i64(), self.end.try_to_i64()) {
            let diff = (end - start) as u64 % self.stride;
            let diff = Bitvector::from_u64(diff).into_resize_unsigned(self.end.bytesize());
            self.start.checked_add_assign(&diff).unwrap();
            if self.start == self.end {
                self.stride = 0;
            }
        } else {
            self.set_stride_to_unknown();
        }
    }

    /// Change the given interval such that it only contains values with the given remainder modulo the given stride.
    /// This may round up the start of the interval and may round down the end of the interval.
    /// If the resulting interval is empty then an error is returned.
    /// This function ignores and replaces the previous stride of the interval.
    ///
    /// For intervals with bytesize greater than 8 this function just returns the unmodified interval.
    pub fn adjust_to_stride_and_remainder(
        self,
        stride: u64,
        remainder: u64,
    ) -> Result<Self, Error> {
        if self.bytesize() > ByteSize::new(8) {
            return Ok(self);
        }
        let (mut start, mut end) = (
            self.start.try_to_i128().unwrap(),
            self.end.try_to_i128().unwrap(),
        );
        let diff = (remainder as i128 - start) % stride as i128;
        let diff = (diff + stride as i128) % stride as i128;
        start += diff;
        let diff = (end - remainder as i128) % stride as i128;
        let diff = (diff + stride as i128) % stride as i128;
        end -= diff;

        if start > i64::MAX as i128 || end < i64::MIN as i128 || start > end {
            return Err(anyhow!("Empty interval"));
        }
        let start = Bitvector::from_i64(start as i64)
            .into_truncate(self.start.bytesize())
            .unwrap();
        let end = Bitvector::from_i64(end as i64)
            .into_truncate(self.end.bytesize())
            .unwrap();
        let stride = if start == end { 0 } else { stride };
        Ok(Interval { start, end, stride })
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
                stride: self.stride,
            }
        } else {
            // The interval either contains both -1 and 0 or wraps around
            if let Ok(start) = self.start.try_to_i128() {
                let stride = 1 << self.stride.trailing_zeros();
                let remainder = (start % stride + stride) % stride;
                Interval {
                    start: Bitvector::zero(width.into()),
                    end: Bitvector::unsigned_max_value(self.end.width())
                        .into_zero_extend(width)
                        .unwrap(),
                    stride: stride as u64,
                }
                .adjust_to_stride_and_remainder(stride as u64, remainder as u64)
                .unwrap()
            } else {
                Interval {
                    start: Bitvector::zero(width.into()),
                    end: Bitvector::unsigned_max_value(self.end.width())
                        .into_zero_extend(width)
                        .unwrap(),
                    stride: 1,
                }
            }
        }
    }

    /// Truncate the bitvectors in the interval
    /// by removing the least significant bytes lower than the `low_byte` from them.
    pub fn subpiece_higher(self, low_byte: ByteSize) -> Self {
        let start = self.start.subpiece(low_byte, self.bytesize() - low_byte);
        let end = self.end.subpiece(low_byte, self.bytesize() - low_byte);
        let stride = !(start == end) as u64;
        Interval {
            start: self.start.subpiece(low_byte, self.bytesize() - low_byte),
            end: self.end.subpiece(low_byte, self.bytesize() - low_byte),
            stride,
        }
    }

    /// Truncate the bitvectors in the interval to `size`,
    /// i.e. the most significant bytes (higher than `size`) are removed from all values.
    pub fn subpiece_lower(self, size: ByteSize) -> Self {
        let length = self.end.clone() - &self.start;
        if length
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
                return Interval {
                    start,
                    end,
                    stride: self.stride,
                };
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

    /// Piece two intervals together, where `self` contains the most signifcant bytes
    /// and `other` contains the least significant bytes of the resulting values.
    pub fn piece(&self, other: &Interval) -> Self {
        if other.start.sign_bit().to_bool() && !other.end.sign_bit().to_bool() {
            // The `other` interval contains both negative and positive values.
            let interval = Interval {
                start: self
                    .start
                    .bin_op(BinOpType::Piece, &Bitvector::zero(other.start.width()))
                    .unwrap(),
                end: self
                    .end
                    .bin_op(BinOpType::Piece, &(-Bitvector::one(other.end.width())))
                    .unwrap(),
                stride: 1,
            };
            if other.bytesize() > ByteSize::new(8) {
                interval
            } else {
                let stride = 1u64 << other.stride.trailing_zeros();
                let remainder = other.start.try_to_i128().unwrap() % stride as i128;
                let remainder = ((remainder + stride as i128) % stride as i128) as u64;
                interval
                    .adjust_to_stride_and_remainder(stride, remainder)
                    .unwrap()
            }
        } else {
            let stride = match (self.stride, other.stride) {
                (0, _) => other.stride,
                (_, 0) => self.stride << other.bytesize().as_bit_length(),
                _ => 1u64 << other.stride.trailing_zeros(),
            };
            Interval {
                start: self.start.bin_op(BinOpType::Piece, &other.start).unwrap(),
                end: self.end.bin_op(BinOpType::Piece, &other.end).unwrap(),
                stride,
            }
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
                stride: self.stride,
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
            Interval {
                start,
                end,
                stride: self.stride.gcd(rhs.stride),
            }
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
            Interval {
                start,
                end,
                stride: self.stride.gcd(rhs.stride),
            }
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
            stride: self.stride.gcd(rhs.stride),
        }
    }

    /// Return `true` if `bitvec` is contained in the strided interval.
    /// Panics if the interval and `bitvec` have different bytesizes.
    pub fn contains(&self, bitvec: &Bitvector) -> bool {
        if self.start == *bitvec {
            return true;
        }
        self.start.checked_sle(bitvec).unwrap() && self.end.checked_sge(bitvec).unwrap() && {
            if let Ok(diff) = (bitvec - &self.start).try_to_u64() {
                self.stride > 0 && diff % self.stride == 0
            } else {
                true
            }
        }
    }
}

impl From<Bitvector> for Interval {
    /// Create an interval that only contains the given bitvector.
    fn from(bitvec: Bitvector) -> Self {
        Interval {
            start: bitvec.clone(),
            end: bitvec,
            stride: 0,
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

/// The extended Euclidean algorithm.
///
/// Returns a triple `(gcd, x, y)` such that `gcd` is the greatest common divisor of `a` and `b`
/// and the following equation holds:
/// ```txt
/// gcd = x*a + y*b
/// ```
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, left_inverse, right_inverse) = extended_gcd(b % a, a);
        (g, right_inverse - (b / a) * left_inverse, left_inverse)
    }
}

/// Compute the stride and the residue class of the intersection of the given intervals using the chinese remainder theorem.
/// The inputs are required to have byte sizes not larger than 8 (= 64bit).
///
/// If the intersection is empty, then `Ok(None)` is returned.
/// If an error occured during the computation (e.g. because of an integer overflow), then an error is returned.
/// Note that this also includes the case where the computed stride is larger than [`u64::MAX`].
fn compute_intersection_residue_class(
    interval_left: &Interval,
    interval_right: &Interval,
) -> Result<Option<(u64, u64)>, Error> {
    match (interval_left.stride, interval_right.stride) {
        (0, 0) => {
            // both intervals contain exactly one value
            if interval_left.start == interval_right.start {
                return Ok(Some((0, 0)));
            } else {
                return Ok(None);
            }
        }
        (0, _) => {
            if interval_right.contains(&interval_left.start) {
                let stride = interval_right.stride as i128;
                let remainder = interval_right.start.try_to_i128()? % stride;
                let remainder = (remainder + stride) % stride;
                return Ok(Some((stride as u64, remainder as u64)));
            } else {
                return Ok(None);
            }
        }
        (_, 0) => {
            if interval_left.contains(&interval_right.start) {
                let stride = interval_left.stride as i128;
                let remainder = interval_left.start.try_to_i128()? % stride;
                let remainder = (remainder + stride) % stride;
                return Ok(Some((stride as u64, remainder as u64)));
            } else {
                return Ok(None);
            }
        }
        _ => (),
    }
    // We compute everything in i128 to reduce the likelihood of integer overflows.
    let (stride_left, stride_right) = (interval_left.stride as i128, interval_right.stride as i128);
    let (base_left, base_right) = (
        interval_left.start.try_to_i64().unwrap() as i128,
        interval_right.start.try_to_i64().unwrap() as i128,
    );
    // The result of the extended euclidean algorithm satisfies
    // `gcd = left_inverse * stride_left + right_inverse * stride_right`.
    // For us most important is the equation system
    // ```
    // left_inverse * stride_left = 0   (modulo stride_left)
    // left_inverse * stride_left = gcd (modulo stride_right)
    // right_inverse * stride_right = gcd   (modulo stride_left)
    // right_inverse * stride_right = 0     (modulo stride_right)
    // ```
    let (gcd, left_inverse, right_inverse) = extended_gcd(stride_left, stride_right);

    if base_left % gcd != base_right % gcd {
        // The residue classes do not intersect, thus the intersection is empty.
        Ok(None)
    } else {
        let lcm = (stride_left / gcd) * stride_right;
        // The residue class of the intersection is computed such that the following equations hold:
        // ```
        // residue_class = base_right   (modulo stride_right)
        // residue_class = base_left    (modulo stride_left)
        // ```
        // The `% lcm` operations are there to reduce the risk of integer overflows
        let residue_class = ((base_right % lcm) / gcd * (left_inverse * stride_left)) % lcm // = base_right / gcd * gcd (modulo stride_right) 
            + ((base_left % lcm) / gcd * (right_inverse * stride_right)) % lcm // = base_left / gcd * gcd (modulo stride_left)
            + base_left % gcd; // = base_left % gcd = base_right % gcd
                               // Ensure that the residue class is not negative
        let residue_class = (residue_class + lcm) % lcm;

        // Since we cannot rule out integer overflows for all possible inputs,
        // we need to check the correctness of the result.
        if lcm <= u64::MAX as i128
            && lcm % stride_left == 0
            && lcm % stride_right == 0
            && (base_left - residue_class) % stride_left == 0
            && (base_right - residue_class) % stride_right == 0
        {
            Ok(Some((lcm as u64, residue_class as u64)))
        } else {
            Err(anyhow!(
                "Integer overflow during chinese remainder theorem computation."
            ))
        }
    }
}

#[cfg(test)]
mod tests;
