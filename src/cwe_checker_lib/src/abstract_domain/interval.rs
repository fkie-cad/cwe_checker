use crate::intermediate_representation::*;
use crate::prelude::*;
use std::convert::TryFrom;

use super::{AbstractDomain, HasTop, RegisterDomain, SizedDomain};

/// An interval of values with a fixed byte size.
/// The interval does not contain any type information,
/// i.e. the values can be interpreted as both signed or unsigned integers.
#[derive(Serialize, Deserialize, Debug, Eq, Hash, Clone)]
struct Interval {
    start: Bitvector,
    end: Bitvector,
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

    pub fn new_top(bytesize: ByteSize) -> Interval {
        Interval {
            start: Bitvector::signed_min_value(bytesize.into()),
            end: Bitvector::signed_max_value(bytesize.into()),
        }
    }

    pub fn is_top(&self) -> bool {
        (self.start.clone() - &Bitvector::one(self.start.width())) == self.end
    }

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

    pub fn subpiece(mut self, low_byte: ByteSize, size: ByteSize) -> Self {
        if self.start == self.end {
            let new_val = self.start.into_checked_lshr(low_byte.as_bit_length())
            .unwrap()
            .into_truncate(size.as_bit_length())
            .unwrap();
            new_val.into()
        } else if low_byte == ByteSize::new(0) {
            self.start.truncate(size.as_bit_length()).unwrap();
            self.end.truncate(size.as_bit_length()).unwrap();
            self
        } else {
            Interval::new_top(size)
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

/// TODO: Write doc comment!
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
        todo!()
    }

    fn un_op(&self, op: UnOpType) -> Self {
        todo!()
    }

    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        let new_interval = self.interval.clone().subpiece(low_byte, size);
        let new_lower_bound = {
            if let Some(bound) = &self.widening_lower_bound {
                todo!()
            };

            todo!()
        };

        todo!()
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
                    Bitvector::from_u64(bitvec.count_ones() as u64)
                        .into_truncate(width)
                        .unwrap()
                        .into()
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

#[cfg(test)]
mod tests;
