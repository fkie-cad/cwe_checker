use std::fmt::Display;

use crate::intermediate_representation::*;
use crate::prelude::*;

use super::{AbstractDomain, HasTop, RegisterDomain, SizedDomain, SpecializeByConditional};
use super::{TryToBitvec, TryToInterval};

mod simple_interval;
pub use simple_interval::*;

mod bin_ops;

/// An abstract domain representing values in an interval range.
///
/// The interval bounds are signed integers,
/// i.e. the domain looses precision if tasked to represent large unsigned integers.
///
/// The domain also contains widening hints to faciliate fast and exact widening for simple loop counter variables.
/// See the [`IntervalDomain::signed_merge_and_widen`] method for details on the widening strategy.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct IntervalDomain {
    /// The underlying interval.
    interval: Interval,
    /// A lower bound for widening operations.
    widening_upper_bound: Option<Bitvector>,
    /// An upper bound for widening operations.
    widening_lower_bound: Option<Bitvector>,
    /// A delay counter to prevent unnecessary widenings.
    /// See the [`IntervalDomain::signed_merge_and_widen`] method for its usage in the widening strategy.
    widening_delay: u64,
}

impl From<Interval> for IntervalDomain {
    /// Generate an interval domain without widening hints.
    fn from(interval: Interval) -> IntervalDomain {
        IntervalDomain {
            interval,
            widening_lower_bound: None,
            widening_upper_bound: None,
            widening_delay: 0,
        }
    }
}

impl IntervalDomain {
    /// Create a new interval domain with the given bounds.
    ///
    /// Both `start` and `end` are inclusive, i.e. contained in the interval.
    /// The widening hints are set to `None`.
    pub fn new(start: Bitvector, end: Bitvector) -> Self {
        IntervalDomain {
            interval: Interval::new(start, end),
            widening_upper_bound: None,
            widening_lower_bound: None,
            widening_delay: 0,
        }
    }

    /// Returns true if the two intervals represent the same value sets.
    /// This function ignores differences in the widening hints of the two intervals.
    pub fn equal_as_value_sets(&self, other: &IntervalDomain) -> bool {
        self.interval == other.interval
    }

    /// If `bound` is more exact/restrictive than the current lower bound of `self`,
    /// set the lower bound to `bound`.
    /// Otherwise keep the old lower bound.
    pub fn update_widening_lower_bound(&mut self, bound: &Option<Bitvector>) {
        if let Some(bound_value) = bound {
            if bound_value.checked_slt(&self.interval.start).unwrap() {
                if let Some(ref previous_bound) = self.widening_lower_bound {
                    if bound_value.checked_sgt(previous_bound).unwrap() {
                        self.widening_lower_bound = Some(bound_value.clone());
                    }
                } else {
                    self.widening_lower_bound = Some(bound_value.clone());
                }
            }
        }
    }

    /// If `bound` is more exact/restrictive than the current upper bound of `self`,
    /// set the upper bound to `bound`.
    /// Otherwise keep the old upper bound.
    pub fn update_widening_upper_bound(&mut self, bound: &Option<Bitvector>) {
        if let Some(bound_value) = bound {
            if bound_value.checked_sgt(&self.interval.end).unwrap() {
                if let Some(ref previous_bound) = self.widening_upper_bound {
                    if bound_value.checked_slt(previous_bound).unwrap() {
                        self.widening_upper_bound = Some(bound_value.clone());
                    }
                } else {
                    self.widening_upper_bound = Some(bound_value.clone());
                }
            }
        }
    }

    /// Merge as signed intervals without performing widenings.
    pub fn signed_merge(&self, other: &IntervalDomain) -> IntervalDomain {
        let mut merged_domain: IntervalDomain = self.interval.signed_merge(&other.interval).into();
        merged_domain.update_widening_lower_bound(&self.widening_lower_bound);
        merged_domain.update_widening_lower_bound(&other.widening_lower_bound);
        merged_domain.update_widening_upper_bound(&self.widening_upper_bound);
        merged_domain.update_widening_upper_bound(&other.widening_upper_bound);
        merged_domain.widening_delay = std::cmp::max(self.widening_delay, other.widening_delay);

        merged_domain
    }

    /// Merge as signed intervals and perform widening if necessary.
    ///
    /// ## Widening Strategy
    ///
    /// ### The widening delay
    ///
    /// Each interval has a `widening_delay` counter,
    /// which denotes the length of the interval after the last time that widening was performed.
    /// For operations with more than one input,
    /// the widening delay is set to the maximum of the input widening delays.
    /// The only exception to this is the [`IntervalDomain::intersect()`] method,
    /// which may lower the value of the widening delay.
    ///
    /// ### When to widen
    ///
    /// If the merged interval equals one of the input intervals as value sets, do not perform widening.
    /// Else widening is performed if and only if the length of the interval is greater than `widening_delay + 2`.
    ///
    /// ### How to widen
    ///
    /// If no suitable widening bounds for widening exist, widen to the `Top` value.
    /// If exactly one widening bound exists, widen up to the bound,
    /// but do not perform widening in the other direction of the interval.
    /// If widening bounds for both directions exist, widen up to the bounds in both directions.
    ///
    /// After that the `widening_delay` is set to the length of the resulting interval.
    pub fn signed_merge_and_widen(&self, other: &IntervalDomain) -> IntervalDomain {
        let mut merged_domain = self.signed_merge(other);
        if merged_domain.equal_as_value_sets(self) || merged_domain.equal_as_value_sets(other) {
            // Do not widen if the value set itself is already contained in either `self` or `other`.
            return merged_domain;
        }
        if let Ok(length) = merged_domain.interval.length().try_to_u64() {
            if length <= merged_domain.widening_delay + 2 {
                // Do not widen for already unconstrained intervals (case length() returning zero)
                // or if the interval length is not larger than `widening_delay + 2`.
                // FIXME: `widening_delay + 2` may overflow.
                // But such a large delay is probably incorrect anyway, so this should not cause unnecessary widenings.
                return merged_domain;
            }
        }
        let mut has_been_widened = false;
        if self.interval.start != other.interval.start
            && merged_domain.widening_lower_bound.is_some()
        {
            // widen to the lower bound
            merged_domain.interval.start = merged_domain.widening_lower_bound.unwrap();
            merged_domain.widening_lower_bound = None;
            has_been_widened = true;
        }
        if self.interval.end != other.interval.end && merged_domain.widening_upper_bound.is_some() {
            // widen to the upper bound
            merged_domain.interval.end = merged_domain.widening_upper_bound.unwrap();
            merged_domain.widening_upper_bound = None;
            has_been_widened = true;
        }
        if has_been_widened {
            merged_domain.widening_delay =
                merged_domain.interval.length().try_to_u64().unwrap_or(0);
            merged_domain
        } else {
            // No widening bounds could be used for widening, so we have to widen to the `Top` value.
            IntervalDomain::new_top(merged_domain.bytesize())
        }
    }

    /// Zero-extend the values in the interval to the given width.
    pub fn zero_extend(self, width: ByteSize) -> IntervalDomain {
        let lower_bound = match self.widening_lower_bound {
            Some(bound)
                if (bound.sign_bit().to_bool() == self.interval.start.sign_bit().to_bool())
                    && (self.interval.start.sign_bit().to_bool()
                        == self.interval.end.sign_bit().to_bool()) =>
            {
                Some(bound.into_zero_extend(width).unwrap())
            }
            _ => None,
        };
        let upper_bound = match self.widening_upper_bound {
            Some(bound)
                if (bound.sign_bit().to_bool() == self.interval.end.sign_bit().to_bool())
                    && (self.interval.start.sign_bit().to_bool()
                        == self.interval.end.sign_bit().to_bool()) =>
            {
                Some(bound.into_zero_extend(width).unwrap())
            }
            _ => None,
        };
        let new_interval = self.interval.zero_extend(width);
        IntervalDomain {
            interval: new_interval,
            widening_lower_bound: lower_bound,
            widening_upper_bound: upper_bound,
            widening_delay: self.widening_delay,
        }
    }

    /// Sign-extend the values in the interval to the given width.
    pub fn sign_extend(self, width: ByteSize) -> Self {
        assert!(self.bytesize() <= width);
        IntervalDomain {
            interval: Interval {
                start: self.interval.start.clone().into_sign_extend(width).unwrap(),
                end: self.interval.end.clone().into_sign_extend(width).unwrap(),
            },
            widening_lower_bound: self
                .widening_lower_bound
                .map(|bitvec| bitvec.into_sign_extend(width).unwrap()),
            widening_upper_bound: self
                .widening_upper_bound
                .map(|bitvec| bitvec.into_sign_extend(width).unwrap()),
            widening_delay: self.widening_delay,
        }
    }

    /// Compute the intersection of two intervals.
    /// Return an error if the intersection is empty.
    pub fn intersect(&self, other: &Self) -> Result<Self, Error> {
        let mut intersected_domain: IntervalDomain =
            self.interval.signed_intersect(&other.interval)?.into();
        intersected_domain.update_widening_lower_bound(&self.widening_lower_bound);
        intersected_domain.update_widening_lower_bound(&other.widening_lower_bound);
        intersected_domain.update_widening_upper_bound(&self.widening_upper_bound);
        intersected_domain.update_widening_upper_bound(&other.widening_upper_bound);
        intersected_domain.widening_delay =
            std::cmp::max(self.widening_delay, other.widening_delay);

        if let Ok(interval_length) = intersected_domain.interval.length().try_to_u64() {
            intersected_domain.widening_delay =
                std::cmp::min(intersected_domain.widening_delay, interval_length);
        }

        Ok(intersected_domain)
    }

    /// Check whether all values in the interval are representable by bitvectors of the given `size`.
    /// Does not check whether this is also true for the widening hints.
    pub fn fits_into_size(&self, size: ByteSize) -> bool {
        if size >= self.bytesize() {
            return true;
        }
        let min = Bitvector::signed_min_value(size.into())
            .into_sign_extend(self.bytesize())
            .unwrap();
        let max = Bitvector::signed_max_value(size.into())
            .into_sign_extend(self.bytesize())
            .unwrap();
        min.checked_sle(&self.interval.start).unwrap()
            && max.checked_sge(&self.interval.end).unwrap()
    }
}

impl SpecializeByConditional for IntervalDomain {
    fn add_signed_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        if let Some(old_upper_bound) = &self.widening_upper_bound {
            if old_upper_bound.checked_sle(bound).unwrap() {
                return Ok(self);
            } else if self.interval.end.checked_slt(bound).unwrap() {
                self.widening_upper_bound = Some(bound.clone());
                return Ok(self);
            } else {
                self.widening_upper_bound = None;
            }
        } else if self.interval.end.checked_slt(bound).unwrap() {
            self.widening_upper_bound = Some(bound.clone());
            return Ok(self);
        }
        // we already know that the bound is less equal to `self.interval.end`
        if self.interval.start.checked_sle(bound).unwrap() {
            self.interval.end = bound.clone();
            Ok(self)
        } else {
            Err(anyhow!("Empty interval"))
        }
    }

    fn add_signed_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        if let Some(old_lower_bound) = &self.widening_lower_bound {
            if old_lower_bound.checked_sge(bound).unwrap() {
                return Ok(self);
            } else if self.interval.start.checked_sgt(bound).unwrap() {
                self.widening_lower_bound = Some(bound.clone());
                return Ok(self);
            } else {
                self.widening_lower_bound = None;
            }
        } else if self.interval.start.checked_sgt(bound).unwrap() {
            self.widening_lower_bound = Some(bound.clone());
            return Ok(self);
        }
        // we already know that the bound is greater equal to `self.interval.start`
        if self.interval.end.checked_sge(bound).unwrap() {
            self.interval.start = bound.clone();
            Ok(self)
        } else {
            Err(anyhow!("Empty interval"))
        }
    }

    fn add_unsigned_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        if bound.sign_bit().to_bool() {
            if self.interval.end.sign_bit().to_bool() {
                self.add_signed_less_equal_bound(bound)
            } else if self.interval.start.sign_bit().to_bool() {
                Ok(self)
            } else {
                self.add_signed_greater_equal_bound(&Bitvector::zero(bound.width()))
            }
        } else {
            self = self.add_signed_greater_equal_bound(&Bitvector::zero(bound.width()))?;
            self.add_signed_less_equal_bound(bound)
        }
    }

    fn add_unsigned_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        if bound.sign_bit().to_bool() {
            self = self.add_signed_less_equal_bound(&(-Bitvector::one(bound.width())))?;
            self.add_signed_greater_equal_bound(bound)
        } else if self.interval.end.checked_slt(bound).unwrap() {
            self.add_signed_less_equal_bound(&(-Bitvector::one(bound.width())))
        } else if self.interval.start.sign_bit().to_bool() {
            Ok(self)
        } else {
            self.add_signed_greater_equal_bound(bound)
        }
    }

    fn add_not_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        if self.interval.start == *bound && self.interval.end == *bound {
            return Err(anyhow!("Empty interval"));
        }
        if self.interval.start.checked_sgt(bound).unwrap() {
            self.add_signed_greater_equal_bound(&(bound + &Bitvector::one(bound.width())))
        } else if self.interval.start == *bound {
            self.interval.start += &Bitvector::one(bound.width());
            Ok(self)
        } else if self.interval.end.checked_slt(bound).unwrap() {
            self.add_signed_less_equal_bound(&(bound - &Bitvector::one(bound.width())))
        } else if self.interval.end == *bound {
            self.interval.end -= &Bitvector::one(bound.width());
            Ok(self)
        } else {
            Ok(self)
        }
    }
}

impl AbstractDomain for IntervalDomain {
    /// Merge two interval domains and perform widening if necessary.
    /// See [`IntervalDomain::signed_merge_and_widen`] for the widening strategy.
    fn merge(&self, other: &IntervalDomain) -> IntervalDomain {
        self.signed_merge_and_widen(other)
    }

    /// Return `true` if the interval spans all possible values.
    fn is_top(&self) -> bool {
        self.interval.is_top()
    }
}

impl SizedDomain for IntervalDomain {
    /// Return the size in bytes of the represented values.
    fn bytesize(&self) -> ByteSize {
        self.interval.start.width().into()
    }

    /// Return a new `Top` value with the given bytesize.
    fn new_top(bytesize: ByteSize) -> Self {
        IntervalDomain {
            interval: Interval {
                start: Bitvector::signed_min_value(bytesize.into()),
                end: Bitvector::signed_max_value(bytesize.into()),
            },
            widening_lower_bound: None,
            widening_upper_bound: None,
            widening_delay: 0,
        }
    }
}

impl HasTop for IntervalDomain {
    /// Return a new interval with the same byte size as `self` and representing the `Top` value of the domain.
    fn top(&self) -> Self {
        Self::new_top(self.bytesize())
    }
}

impl RegisterDomain for IntervalDomain {
    /// Compute the result of a binary operation between two interval domains.
    ///
    /// For binary operations that are not explicitly implemented
    /// the result is only exact if both intervals contain exactly one value.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        match op {
            Piece | IntEqual | IntNotEqual | IntLess | IntSLess | IntLessEqual | IntSLessEqual
            | IntCarry | IntSCarry | IntSBorrow | IntAnd | IntOr | IntXOr | IntRight
            | IntSRight | IntDiv | IntSDiv | IntRem | IntSRem | BoolAnd | BoolOr | BoolXOr
            | FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual | FloatAdd | FloatSub
            | FloatMult | FloatDiv => {
                let new_interval = if self.interval.start == self.interval.end
                    && rhs.interval.start == rhs.interval.end
                {
                    if let Ok(bitvec) = self.interval.start.bin_op(op, &rhs.interval.start) {
                        bitvec.into()
                    } else {
                        Interval::new_top(self.bin_op_bytesize(op, rhs))
                    }
                } else {
                    Interval::new_top(self.bin_op_bytesize(op, rhs))
                };
                IntervalDomain {
                    interval: new_interval,
                    widening_lower_bound: None,
                    widening_upper_bound: None,
                    widening_delay: std::cmp::max(self.widening_delay, rhs.widening_delay),
                }
            }
            IntAdd => self.add(rhs),
            IntSub => self.sub(rhs),
            IntMult => self.signed_mul(rhs),
            IntLeft => self.shift_left(rhs),
        }
    }

    /// Compute the result of an unary operation on the interval domain.
    fn un_op(&self, op: UnOpType) -> Self {
        use UnOpType::*;
        match op {
            Int2Comp => {
                let interval = self.interval.clone().int_2_comp();
                let mut new_upper_bound = None;
                if let Some(bound) = self.widening_lower_bound.clone() {
                    if bound
                        .checked_sgt(&Bitvector::signed_min_value(self.bytesize().into()))
                        .unwrap()
                    {
                        new_upper_bound = Some(-bound);
                    }
                };
                let new_lower_bound = self.widening_upper_bound.clone().map(|bound| -bound);
                IntervalDomain {
                    interval,
                    widening_lower_bound: new_lower_bound,
                    widening_upper_bound: new_upper_bound,
                    widening_delay: self.widening_delay,
                }
            }
            IntNegate => IntervalDomain {
                interval: self.interval.clone().bitwise_not(),
                widening_lower_bound: None,
                widening_upper_bound: None,
                widening_delay: self.widening_delay,
            },
            BoolNegate => {
                if self.interval.start == self.interval.end {
                    if self.interval.start == Bitvector::zero(ByteSize::new(1).into()) {
                        Bitvector::one(ByteSize::new(1).into()).into()
                    } else {
                        Bitvector::zero(ByteSize::new(1).into()).into()
                    }
                } else {
                    IntervalDomain::new_top(self.bytesize())
                }
            }
            FloatAbs | FloatCeil | FloatFloor | FloatNaN | FloatNegate | FloatRound | FloatSqrt => {
                IntervalDomain::new_top(self.bytesize())
            }
        }
    }

    /// Take a sub-bitvector of the values in the interval domain.
    ///
    /// If `low_byte` is not zero, the result will generally be not exact.
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        let new_interval = self.interval.clone().subpiece(low_byte, size);
        let (mut new_lower_bound, mut new_upper_bound) = (None, None);
        if low_byte == ByteSize::new(0) {
            if let (Some(lower_bound), Some(upper_bound)) =
                (&self.widening_lower_bound, &self.widening_upper_bound)
            {
                let new_min = Bitvector::signed_min_value(size.into())
                    .into_sign_extend(self.bytesize())
                    .unwrap();
                let new_max = Bitvector::signed_max_value(size.into())
                    .into_sign_extend(self.bytesize())
                    .unwrap();
                if lower_bound.checked_sge(&new_min).unwrap()
                    && upper_bound.checked_sle(&new_max).unwrap()
                {
                    new_lower_bound = Some(lower_bound.clone().into_truncate(size).unwrap());
                    new_upper_bound = Some(upper_bound.clone().into_truncate(size).unwrap());
                }
            }
        }
        IntervalDomain {
            interval: new_interval,
            widening_lower_bound: new_lower_bound,
            widening_upper_bound: new_upper_bound,
            widening_delay: self.widening_delay,
        }
    }

    /// Compute the result of a cast operation on the interval domain.
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self {
        use CastOpType::*;
        match kind {
            IntZExt => {
                assert!(self.bytesize() <= width);
                if self.bytesize() == width {
                    return self.clone();
                }
                self.clone().zero_extend(width)
            }
            IntSExt => {
                assert!(self.bytesize() <= width);
                self.clone().sign_extend(width)
            }
            Float2Float | Int2Float | Trunc => IntervalDomain::new_top(width),
            PopCount => {
                if let Ok(bitvec) = self.try_to_bitvec() {
                    bitvec.cast(kind, width).unwrap().into()
                } else {
                    IntervalDomain::new(
                        Bitvector::zero(width.into()),
                        Bitvector::from_u64(self.bytesize().as_bit_length() as u64)
                            .into_truncate(width)
                            .unwrap(),
                    )
                }
            }
        }
    }
}

impl std::ops::Add for IntervalDomain {
    type Output = IntervalDomain;

    fn add(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntAdd, &rhs)
    }
}

impl std::ops::Sub for IntervalDomain {
    type Output = IntervalDomain;

    fn sub(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntSub, &rhs)
    }
}

impl std::ops::Neg for IntervalDomain {
    type Output = IntervalDomain;

    fn neg(self) -> Self {
        self.un_op(UnOpType::Int2Comp)
    }
}

impl From<Bitvector> for IntervalDomain {
    /// Create an interval containing only `bitvec`.
    fn from(bitvec: Bitvector) -> Self {
        IntervalDomain {
            interval: bitvec.into(),
            widening_lower_bound: None,
            widening_upper_bound: None,
            widening_delay: 0,
        }
    }
}

impl TryToBitvec for IntervalDomain {
    /// If the domain represents an interval of length one, return the contained value.
    fn try_to_bitvec(&self) -> Result<Bitvector, Error> {
        if self.interval.start == self.interval.end {
            Ok(self.interval.start.clone())
        } else {
            Err(anyhow!("More than one value in the interval."))
        }
    }
}

impl TryToInterval for IntervalDomain {
    /// If the domain represents a bounded (i.e. not `Top`) interval, return it.
    fn try_to_interval(&self) -> Result<Interval, Error> {
        if self.is_top() {
            Err(anyhow!("Value is Top"))
        } else {
            Ok(self.interval.clone())
        }
    }
}

impl Display for IntervalDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_top() {
            write!(f, "Top:i{}", self.bytesize().as_bit_length())
        } else if self.interval.start == self.interval.end {
            write!(
                f,
                "0x{:016x}:i{}",
                apint::Int::from(self.interval.start.clone()),
                self.bytesize().as_bit_length()
            )
        } else {
            let start_int = apint::Int::from(self.interval.start.clone());
            let end_int = apint::Int::from(self.interval.end.clone());
            write!(
                f,
                "[0x{:016x}, 0x{:016x}]:i{}",
                start_int,
                end_int,
                self.bytesize().as_bit_length()
            )
        }
    }
}

#[cfg(test)]
mod tests;
