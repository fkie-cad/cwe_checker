use super::*;

impl IntervalDomain {
    /// Compute the interval of possible results
    /// if one adds a value from `self` to a value from `rhs`.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut interval: IntervalDomain = self.interval.add(&rhs.interval).into();
        if interval.is_top() {
            interval
        } else {
            interval.widening_delay = std::cmp::max(self.widening_delay, rhs.widening_delay);
            interval.update_widening_lower_bound(
                &self
                    .widening_lower_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_add_overflow_checked(&rhs.interval.start)),
            );
            interval.update_widening_lower_bound(
                &rhs.widening_lower_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_add_overflow_checked(&self.interval.start)),
            );
            interval.update_widening_upper_bound(
                &self
                    .widening_upper_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_add_overflow_checked(&rhs.interval.end)),
            );
            interval.update_widening_upper_bound(
                &rhs.widening_upper_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_add_overflow_checked(&self.interval.end)),
            );
            interval
        }
    }

    /// Compute the interval of possible results
    /// if one subtracts a value in `rhs` from a value in `self`.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut interval: IntervalDomain = self.interval.sub(&rhs.interval).into();
        if interval.is_top() {
            interval
        } else {
            interval.widening_delay = std::cmp::max(self.widening_delay, rhs.widening_delay);
            interval.update_widening_lower_bound(
                &self
                    .widening_lower_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_sub_overflow_checked(&rhs.interval.end)),
            );
            interval.update_widening_lower_bound(
                &rhs.widening_upper_bound
                    .as_ref()
                    .and_then(|bound| self.interval.start.signed_sub_overflow_checked(bound)),
            );
            interval.update_widening_upper_bound(
                &self
                    .widening_upper_bound
                    .as_ref()
                    .and_then(|bound| bound.signed_sub_overflow_checked(&rhs.interval.start)),
            );
            interval.update_widening_upper_bound(
                &rhs.widening_lower_bound
                    .as_ref()
                    .and_then(|bound| self.interval.end.signed_sub_overflow_checked(bound)),
            );
            interval
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
                widening_delay: std::cmp::max(self.widening_delay, rhs.widening_delay),
            }
        }
    }

    /// Compute the resulting interval after a left shift operation.
    /// The result is only exact if the `rhs` interval contains exactly one value.
    pub fn shift_left(&self, rhs: &Self) -> Self {
        if rhs.interval.start == rhs.interval.end {
            let shift_amount = rhs.interval.start.try_to_u64().unwrap() as usize;
            if shift_amount < self.bytesize().as_bit_length() {
                let multiplicator = Bitvector::one(self.bytesize().into())
                    .into_checked_shl(shift_amount)
                    .unwrap();
                self.signed_mul(&multiplicator.into())
            } else {
                Bitvector::zero(self.bytesize().into()).into()
            }
        } else {
            Self::new_top(self.bytesize())
        }
    }
}
