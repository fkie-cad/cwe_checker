use std::collections::{HashMap, HashSet};

use crate::abstract_domain::TryToInterval;
use crate::{
    abstract_domain::{AbstractDomain, HasTop, IntervalDomain, MemRegion, SizedDomain},
    intermediate_representation::{ByteSize, Tid},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InitializationStatus {
    Init { addresses: HashSet<Tid> },
    MaybeInit { addresses: HashSet<Tid> },
    Uninit,
}

impl InitializationStatus {
    /// Merge for intra block tracking
    ///
    /// Any `InitializationStatus` merged with `Init` results in `Init`.
    pub fn merge_precise(&self, other: &Self) -> Self {
        match (self, other) {
            (InitializationStatus::Init { addresses }, InitializationStatus::Uninit)
            | (InitializationStatus::Uninit, InitializationStatus::Init { addresses }) => {
                InitializationStatus::Init {
                    addresses: addresses.clone(),
                }
            }
            (
                InitializationStatus::Init { addresses },
                InitializationStatus::MaybeInit { addresses: a },
            )
            | (
                InitializationStatus::MaybeInit { addresses },
                InitializationStatus::Init { addresses: a },
            ) => InitializationStatus::Init {
                addresses: addresses.union(a).cloned().collect(),
            },
            _ => self.merge(other),
        }
    }
}

impl AbstractDomain for InitializationStatus {
    /// Merge for inter block tracking
    ///
    /// Same `InitializationStatus` are kept.
    /// Introduces `MaybeInit` if `Init` and `Uninit` are merged.
    /// Keeps `MaybeInit` if any parameter is `MaybeInit`.
    fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            (
                InitializationStatus::Init { addresses },
                InitializationStatus::Init { addresses: a },
            ) => InitializationStatus::Init {
                addresses: addresses.union(a).cloned().collect(),
            },
            (InitializationStatus::Uninit, InitializationStatus::Uninit) => {
                InitializationStatus::Uninit
            }

            (
                InitializationStatus::MaybeInit { addresses },
                InitializationStatus::Init { addresses: a },
            )
            | (
                InitializationStatus::MaybeInit { addresses },
                InitializationStatus::MaybeInit { addresses: a },
            )
            | (
                InitializationStatus::Init { addresses },
                InitializationStatus::MaybeInit { addresses: a },
            ) => InitializationStatus::MaybeInit {
                addresses: addresses.union(a).cloned().collect(),
            },
            (InitializationStatus::MaybeInit { addresses }, InitializationStatus::Uninit)
            | (InitializationStatus::Uninit, InitializationStatus::Init { addresses })
            | (InitializationStatus::Uninit, InitializationStatus::MaybeInit { addresses })
            | (InitializationStatus::Init { addresses }, InitializationStatus::Uninit) => {
                InitializationStatus::MaybeInit {
                    addresses: addresses.clone(),
                }
            }
        }
    }

    fn is_top(&self) -> bool {
        if let &InitializationStatus::Uninit = self {
            return true;
        }
        false
    }
}

impl SizedDomain for InitializationStatus {
    fn bytesize(&self) -> ByteSize {
        ByteSize::new(1)
    }

    fn new_top(_bytesize: ByteSize) -> Self {
        InitializationStatus::Uninit
    }
}

impl HasTop for InitializationStatus {
    fn top(&self) -> Self {
        InitializationStatus::Uninit
    }
}

impl MemRegion<InitializationStatus> {
    /// Returns the `InitializationStatus` at the given offset.
    ///
    /// If no value at the offset is present `InitalizationStatus::Uninit` is returned.
    pub fn get_init_status_at_byte_index(&self, index: i64) -> InitializationStatus {
        if let Some(status) = self.entry_map().get(&index) {
            status.clone()
        } else {
            InitializationStatus::Uninit
        }
    }

    /// Returns true if the `MemRegion` contains at least one `InitalizationStatus::Uninit` value
    /// within the given offset interval.
    ///
    /// Note that values not set are treated as `InitalizationStatus::Uninit`. Positive offsets can be ignored, which
    /// in fact treats them as initialized.
    pub fn contains_uninit_within_interval(
        &self,
        interval: &IntervalDomain,
        ignore_non_neg_offsets: bool,
    ) -> Option<bool> {
        if let Ok((lower_bound, upper_bound)) = interval.try_to_offset_interval().as_mut() {
            if ignore_non_neg_offsets {
                if *lower_bound > 0 && *upper_bound > 0 {
                    return Some(false);
                } else if *lower_bound > 0 {
                    *lower_bound = 0;
                }
            }
            for i in *lower_bound..=*upper_bound {
                if let InitializationStatus::Uninit = self.get_init_status_at_byte_index(i) {
                    return Some(true);
                }
            }
            Some(false)
        } else {
            None
        }
    }

    /// Returns true if the `MemRegion` contains at least one `InitalizationStatus::MaybeInit` value
    /// within the given offset interval.
    ///
    /// Positive offsets can be ignored, which in fact treats them as initialized.
    pub fn get_maybe_init_locatons_within_interval(
        &self,
        interval: &IntervalDomain,
        ignore_non_neg_offsets: bool,
    ) -> Option<HashMap<i64, HashSet<Tid>>> {
        let mut maybe_init = HashMap::new();

        if let Ok((lower_bound, upper_bound)) = interval.try_to_offset_interval().as_mut() {
            if upper_bound.clone() - lower_bound.clone() < 256 {
                if ignore_non_neg_offsets {
                    if *lower_bound > 0 {
                        *lower_bound = 0;
                    }
                    if *upper_bound > 0 {
                        *upper_bound = 0;
                    }
                }
                for i in *lower_bound..=*upper_bound {
                    if let InitializationStatus::MaybeInit { addresses } =
                        self.get_init_status_at_byte_index(i)
                    {
                        maybe_init.insert(i, addresses);
                    }
                }
            } else {
                return None;
            }
        }
        if maybe_init.is_empty() {
            return None;
        }
        Some(maybe_init)
    }

    /// Inserts an `InitalizationStatus` at multiple offsets, utilizing the `merge()` function.
    pub fn merge_interval(&mut self, status: &InitializationStatus, interval: &IntervalDomain) {
        if let Ok((lower_bound, higher_bound)) = interval.try_to_offset_interval() {
            for i in lower_bound..=higher_bound {
                if let Some(init_status) = self.entry_map().get(&i) {
                    self.insert_at_byte_index(init_status.merge(status), i);
                } else {
                    self.insert_at_byte_index(InitializationStatus::Uninit.merge(status), i);
                }
            }
        }
    }

    /// Merges `status` into `self` at `offset` utilizing `InitializationStatus::merge()`.
    pub fn merge_at_byte_index(&mut self, offset: i64, status: &InitializationStatus) {
        self.insert_at_byte_index(
            self.get_init_status_at_byte_index(offset).merge(status),
            offset,
        )
    }

    /// Merges `status` into `self` at `offset` utilizing `InitializationStatus::merge_precise()`.
    pub fn merge_precise_at_byte_index(&mut self, offset: i64, status: &InitializationStatus) {
        self.insert_at_byte_index(
            self.get_init_status_at_byte_index(offset)
                .merge_precise(status),
            offset,
        )
    }

    /// Merges `other` MemRegion into `self` utilizing `MemRegion<InitializationStatus>::merge()`.
    pub fn merge(&mut self, other: &MemRegion<InitializationStatus>) {
        // cover all init and maybeinit in other
        for (offset, status) in other.entry_map().iter() {
            self.merge_at_byte_index(*offset, status);
        }
        // cover all offsets in self, that are uninit in other
        for (offset, _status) in self.clone().entry_map() {
            if let InitializationStatus::Uninit = other.get_init_status_at_byte_index(*offset) {
                self.merge_at_byte_index(*offset, &InitializationStatus::Uninit);
            }
        }
    }
}
