use crate::intermediate_representation::*;
use crate::prelude::*;

use super::{AbstractDomain, HasTop, RegisterDomain, SizedDomain};

mod simple_interval;
use simple_interval::*;

/// TODO: Write doc comment!
/// TODO: implementation as interval of signed integers with widening hints
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct IntervalDomain {
    interval: Interval,
    widening_upper_bound: Option<Bitvector>,
    widening_lower_bound: Option<Bitvector>,
}

impl From<Interval> for IntervalDomain {
    fn from(interval: Interval) -> IntervalDomain {
        IntervalDomain {
            interval,
            widening_lower_bound: None,
            widening_upper_bound: None,
        }
    }
}

impl IntervalDomain {
    /// Create a new interval domain with the given bounds.
    ///
    /// Both `start` and `end` are inclusive, i.e. contained in the interval.
    pub fn new(start: Bitvector, end: Bitvector) -> Self {
        IntervalDomain {
            interval: Interval::new(start, end),
            widening_upper_bound: None,
            widening_lower_bound: None,
        }
    }

    /// Returns true if the two strided intervals represent the same value sets.
    /// This function ignores differences in the widening hints of the two strided intervals.
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

        merged_domain
    }

    /// Merge as signed intervals and perform widening if necessary.
    ///
    /// No widening is performed for very small intervals
    /// or if the interval (as value set) is the same for `self` and `other`.
    /// If no suitable widening bounds for widening exist, widen to the `Top` value.
    pub fn signed_merge_and_widen(&self, other: &IntervalDomain) -> IntervalDomain {
        let mut merged_domain = self.signed_merge(other);
        if merged_domain.equal_as_value_sets(self) || merged_domain.equal_as_value_sets(other) {
            // Do not widen if the value set itself is already contained in either `self` or `other`.
            return merged_domain;
        }
        if let Ok(length) = merged_domain.interval.length().try_to_u64() {
            if length <= 2 {
                // Do not widen for very small intervals
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
            merged_domain
        } else {
            // No widening bounds could be used for widening, so we have to widen to the `Top` value.
            IntervalDomain::new_top(merged_domain.bytesize())
        }
    }

    pub fn try_to_bitvec(&self) -> Result<Bitvector, ()> {
        if self.interval.start == self.interval.end {
            Ok(self.interval.start.clone())
        } else {
            Err(())
        }
    }

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
        let mut upper_bound = match self.widening_upper_bound {
            Some(bound)
                if (bound.sign_bit().to_bool() == self.interval.end.sign_bit().to_bool())
                    && (self.interval.start.sign_bit().to_bool()
                        == self.interval.end.sign_bit().to_bool()) =>
            {
                Some(bound.into_zero_extend(width).unwrap())
            }
            _ => None,
        };
        let old_width = self.interval.start.width();
        let new_interval = self.interval.zero_extend(width);
        if upper_bound.is_none() {
            let max_val = Bitvector::unsigned_max_value(old_width)
                .into_zero_extend(width)
                .unwrap();
            if new_interval.end.checked_ult(&max_val).unwrap() {
                upper_bound = Some(max_val);
            }
        }
        IntervalDomain {
            interval: new_interval,
            widening_lower_bound: lower_bound,
            widening_upper_bound: upper_bound,
        }
    }

    pub fn sign_extend(mut self, width: ByteSize) -> Self {
        assert!(self.bytesize() <= width);
        if self.widening_lower_bound.is_none() {
            let min_val = Bitvector::signed_min_value(self.interval.start.width());
            if min_val.checked_slt(&self.interval.start).unwrap() {
                self.widening_lower_bound = Some(min_val);
            }
        }
        if self.widening_upper_bound.is_none() {
            let max_val = Bitvector::signed_max_value(self.interval.end.width());
            if max_val.checked_sgt(&self.interval.end).unwrap() {
                self.widening_upper_bound = Some(max_val);
            }
        }
        IntervalDomain {
            interval: Interval {
                start: self.interval.start.clone().into_sign_extend(width).unwrap(),
                end: self.interval.end.clone().into_sign_extend(width).unwrap(),
            },
            widening_lower_bound: self
                .widening_lower_bound
                .clone()
                .map(|bitvec| bitvec.into_sign_extend(width).unwrap()),
            widening_upper_bound: self
                .widening_upper_bound
                .clone()
                .map(|bitvec| bitvec.into_sign_extend(width).unwrap()),
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let interval = self.interval.add(&rhs.interval);
        if interval.is_top() {
            interval.into()
        } else {
            let new_lower_bound = if let (Some(self_bound), Some(rhs_bound)) =
                (&self.widening_lower_bound, &rhs.widening_lower_bound)
            {
                if self_bound.signed_add_overflow_check(rhs_bound) {
                    None
                } else {
                    Some(self_bound.clone().into_checked_add(rhs_bound).unwrap())
                }
            } else {
                None
            };
            let new_upper_bound = if let (Some(self_bound), Some(rhs_bound)) =
                (&self.widening_upper_bound, &rhs.widening_upper_bound)
            {
                if self_bound.signed_add_overflow_check(rhs_bound) {
                    None
                } else {
                    Some(self_bound.clone().into_checked_add(rhs_bound).unwrap())
                }
            } else {
                None
            };
            IntervalDomain {
                interval,
                widening_upper_bound: new_upper_bound,
                widening_lower_bound: new_lower_bound,
            }
        }
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let interval = self.interval.sub(&rhs.interval);
        if interval.is_top() {
            interval.into()
        } else {
            let new_lower_bound = if let (Some(self_bound), Some(rhs_bound)) =
                (&self.widening_lower_bound, &rhs.widening_upper_bound)
            {
                if self_bound.signed_sub_overflow_check(rhs_bound) {
                    None
                } else {
                    Some(self_bound.clone().into_checked_sub(rhs_bound).unwrap())
                }
            } else {
                None
            };
            let new_upper_bound = if let (Some(self_bound), Some(rhs_bound)) =
                (&self.widening_upper_bound, &rhs.widening_lower_bound)
            {
                if self_bound.signed_sub_overflow_check(rhs_bound) {
                    None
                } else {
                    Some(self_bound.clone().into_checked_sub(rhs_bound).unwrap())
                }
            } else {
                None
            };
            IntervalDomain {
                interval,
                widening_upper_bound: new_upper_bound,
                widening_lower_bound: new_lower_bound,
            }
        }
    }

    pub fn signed_mul(&self, rhs: &Self) -> Self {
        let interval = self.interval.signed_mul(&rhs.interval);
        if interval.is_top() {
            interval.into()
        } else {
            let mut possible_bounds = Vec::new();
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_lower_bound, &rhs.widening_lower_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2) {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_lower_bound, &rhs.widening_upper_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2) {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_upper_bound, &rhs.widening_lower_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2) {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_upper_bound, &rhs.widening_upper_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2) {
                    possible_bounds.push(result);
                }
            }
            let mut lower_bound: Option<Bitvector> = None;
            for bound in possible_bounds.iter() {
                if bound.checked_slt(&interval.start).unwrap() {
                    match lower_bound {
                        Some(prev_bound) if prev_bound.checked_slt(bound).unwrap() => {
                            lower_bound = Some(bound.clone())
                        }
                        None => lower_bound = Some(bound.clone()),
                        _ => (),
                    }
                }
            }
            let mut upper_bound: Option<Bitvector> = None;
            for bound in possible_bounds.iter() {
                if bound.checked_sgt(&interval.end).unwrap() {
                    match upper_bound {
                        Some(prev_bound) if prev_bound.checked_sgt(bound).unwrap() => {
                            upper_bound = Some(bound.clone())
                        }
                        None => upper_bound = Some(bound.clone()),
                        _ => (),
                    }
                }
            }
            IntervalDomain {
                interval,
                widening_lower_bound: lower_bound,
                widening_upper_bound: upper_bound,
            }
        }
    }

    pub fn shift_left(&self, rhs: &Self) -> Self {
        if rhs.interval.start == rhs.interval.end {
            let multiplicator = Bitvector::one(self.bytesize().into())
                .into_checked_shl(rhs.interval.start.try_to_u64().unwrap() as usize)
                .unwrap();
            self.signed_mul(&multiplicator.into())
        } else {
            Self::new_top(self.bytesize())
        }
    }
}

impl AbstractDomain for IntervalDomain {
    /// Merge two interval domains and perform widening if necessary.
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
        }
    }
}

impl HasTop for IntervalDomain {
    fn top(&self) -> Self {
        Self::new_top(self.bytesize())
    }
}

impl RegisterDomain for IntervalDomain {
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
                }
            }
            IntAdd => self.add(rhs),
            IntSub => self.sub(rhs),
            IntMult => self.signed_mul(rhs),
            IntLeft => self.shift_left(rhs),
        }
    }

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
                }
            }
            IntNegate => IntervalDomain {
                interval: self.interval.clone().bitwise_not(),
                widening_lower_bound: None,
                widening_upper_bound: None,
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
        }
    }

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

impl From<Bitvector> for IntervalDomain {
    /// Create an interval containing only `bitvec`.
    fn from(bitvec: Bitvector) -> Self {
        IntervalDomain {
            interval: bitvec.into(),
            widening_lower_bound: None,
            widening_upper_bound: None,
        }
    }
}

#[cfg(test)]
mod tests;
