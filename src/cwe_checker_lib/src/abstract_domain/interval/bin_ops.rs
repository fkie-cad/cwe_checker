use super::*;

impl IntervalDomain {
    /// Compute the interval of possible results
    /// if one adds a value from `self` to a value from `rhs`.
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

    /// Compute the interval of possible results
    /// if one subtracts a value in `rhs` from a value in `self`.
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

    /// Compute the interval of possible results
    /// if one multiplies a value in `self` with a value in `rhs`.
    pub fn signed_mul(&self, rhs: &Self) -> Self {
        let interval = self.interval.signed_mul(&rhs.interval);
        if interval.is_top() {
            interval.into()
        } else {
            let mut possible_bounds = Vec::new();
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_lower_bound, &rhs.widening_lower_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2).unwrap() {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_lower_bound, &rhs.widening_upper_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2).unwrap() {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_upper_bound, &rhs.widening_lower_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2).unwrap() {
                    possible_bounds.push(result);
                }
            }
            if let (Some(bound1), Some(bound2)) =
                (&self.widening_upper_bound, &rhs.widening_upper_bound)
            {
                if let (result, false) = bound1.signed_mult_with_overflow_flag(bound2).unwrap() {
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

    /// Compute the resulting interval after a left shift operation.
    /// The result is only exact if the `rhs` interval contains exactly one value.
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
