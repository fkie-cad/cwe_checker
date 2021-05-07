//! This module implements the widening operator for the BrickDomain and BricksDomain.
//! The exact widening procedure depends on three constants.
//!  - The *interval threshold* overapproximates the number of times string sequences can occur in a brick.
//!  - The *sequence threshold* overapproximates the number of string sequences in a brick by forcing a *Top* value.
//!  - The *length threshold* overapproximates the number of bricks in the BricksDomain and forces a *Top* value.
//! A merge is processed without widening when none of the thresholds are exceeded.

use std::{
    cmp::{max, min},
    collections::BTreeSet,
};

use crate::abstract_domain::AbstractDomain;

use super::{brick::Brick, BrickDomain, BricksDomain};

pub const INTERVAL_THRESHOLD: usize = 8;
pub const SEQUENCE_THRESHOLD: usize = 8;
pub const LENGTH_THRESHOLD: usize = 8;

impl BricksDomain {
    /// The widen function of the BricksDomain widens the values during a merge.
    /// If the two BrickDomain lists are not comparable or either list exceeds
    /// the length threshold, *Top* is returned.
    /// Otherwise, the shorter list is padded and the widen function of the
    /// BrickDomain is applied to each element in both lists.
    /// If after the widening all BrickDomain values are *Top*, return
    /// the *Top* value for the BricksDomain.
    pub fn widen(&self, other: &BricksDomain) -> Self {
        let self_num_of_bricks = self.unwrap_value().len();
        let other_num_of_bricks = other.unwrap_value().len();

        let mut new_self = self.clone();
        let mut new_other = other.clone();
        if self_num_of_bricks < other_num_of_bricks {
            new_self = self.pad_list(other);
        } else if other_num_of_bricks < self_num_of_bricks {
            new_other = other.pad_list(self);
        }

        if !new_self.is_less_or_equal(other) && !new_other.is_less_or_equal(self)
            || self_num_of_bricks > LENGTH_THRESHOLD
            || other_num_of_bricks > LENGTH_THRESHOLD
        {
            return BricksDomain::Top;
        }

        let mut widened_brick_domain_list: Vec<BrickDomain> = Vec::new();

        for (self_brick, other_brick) in new_self
            .unwrap_value()
            .iter()
            .zip(new_other.unwrap_value().iter())
        {
            widened_brick_domain_list.push(self_brick.merge(other_brick));
        }

        if BricksDomain::all_bricks_are_top(&widened_brick_domain_list) {
            return BricksDomain::Top;
        }

        BricksDomain::Value(widened_brick_domain_list)
    }

    /// Checks whether all bricks of the BricksDomain are *Top* values.
    /// If so, the BricksDomain itself is converted into a *Top* value.
    pub fn all_bricks_are_top(bricks: &Vec<BrickDomain>) -> bool {
        bricks.iter().all(|brick| match brick {
            BrickDomain::Top => true,
            _ => false,
        })
    }

    /// Checks whether the current BricksDomain is less or equal than the other BricksDomain
    /// by definition of the partial order.
    pub fn is_less_or_equal(&self, other: &BricksDomain) -> bool {
        self.unwrap_value()
            .iter()
            .zip(other.unwrap_value().iter())
            .all(|(self_brick, other_brick)| self_brick.is_less_or_equal(other_brick))
    }
}

impl BrickDomain {
    /// The widen function of the BrickDomain takes the union of both
    /// BrickDomains and returns *Top* if the number of sequences exceeds
    /// a certain threshold.
    /// If neither of the domains are *Top*, the minimum and maximum
    /// of the interval bounds are taken and it is checked whether
    /// their difference exceeds a certain threshold.
    /// If so *min* is set to 0 and *max* is set to infinity (here Max value of 32 bits).
    /// Otherwise, their values are taken as new bounds for the merged domain.
    pub fn widen(&self, other: &BrickDomain) -> Self {
        let self_brick = self.unwrap_value();
        let other_brick = other.unwrap_value();
        let merged_sequence = self_brick
            .get_sequence()
            .union(other_brick.get_sequence())
            .cloned()
            .collect::<BTreeSet<String>>();

        if merged_sequence.len() > SEQUENCE_THRESHOLD {
            return BrickDomain::Top;
        }

        let mut widened_brick = Brick::new();
        let min_bound = min(self_brick.get_min(), other_brick.get_min());
        let max_bound = max(self_brick.get_max(), other_brick.get_max());

        if max_bound - min_bound > INTERVAL_THRESHOLD as u32 {
            widened_brick.set_min(0);
            widened_brick.set_max(u32::MAX);
        } else {
            widened_brick.set_min(min_bound);
            widened_brick.set_max(max_bound);
        }

        widened_brick.set_sequence(merged_sequence);

        BrickDomain::Value(widened_brick)
    }

    /// Checks whether the current BrickDomain is less or equal than the other BrickDomain
    /// by definition of the partial order.
    /// Empty strings are ignored for order comparisons.
    pub fn is_less_or_equal(&self, other: &BrickDomain) -> bool {
        match (self.is_top(), other.is_top()) {
            (false, false) => {
                let self_brick = self.unwrap_value();
                let other_brick = other.unwrap_value();
                if self_brick.is_empty_string() || other_brick.is_empty_string() {
                    return true;
                }
                if self_brick
                    .get_sequence()
                    .is_subset(other_brick.get_sequence())
                    && self_brick.get_min() >= other_brick.get_min()
                    && self_brick.get_max() <= other_brick.get_max()
                {
                    return true;
                }

                false
            }
            (true, false) => false,
            (false, true) | (true, true) => true,
        }
    }
}
