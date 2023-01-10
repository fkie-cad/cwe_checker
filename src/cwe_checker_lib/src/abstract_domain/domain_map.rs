use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use super::*;

/// A `DomainMap<Key, Value, MapMergeStrategy>` is a wrapper type around a `BTreeMap<Key, Value>
/// where the `Value` type is an abstract domain and the map itself is also an abstract domain.
///
/// For example, a map from registers to an abstract domain representing the contained values
/// can be represented by a `DomainMap`.
///
/// A `DomainMap` has two main advantages over a regular `BTreeMap`:
/// * The map itself is wrapped into an `Arc<..>` to enable cheap cloning of `DomainMaps`.
/// * The `DomainMap` automatically implements the [`AbstractDomain`] trait
/// according to the provided [`MapMergeStrategy`] used for merging two maps.
///
/// Since a `DomainMap` implements the `Deref` and `DerefMut` traits with target the inner `BTreeMap`,
/// it can be used just like a `BTreeMap`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V>,
{
    inner: Arc<BTreeMap<K, V>>,
    phantom: PhantomData<S>,
}

impl<K, V, S> Deref for DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V>,
{
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K, V, S> DerefMut for DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V>,
{
    fn deref_mut(&mut self) -> &mut BTreeMap<K, V> {
        Arc::make_mut(&mut self.inner)
    }
}

impl<K, V, S> From<BTreeMap<K, V>> for DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V>,
{
    /// Generate a new `DomainMap` from the `BTreeMap` that it should contain.
    fn from(map: BTreeMap<K, V>) -> Self {
        DomainMap {
            inner: Arc::new(map),
            phantom: PhantomData,
        }
    }
}

impl<K, V, S> FromIterator<(K, V)> for DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V>,
{
    /// Generate a new `DomainMap` from an iterator over the key-value pairs that it should contain.
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
    {
        DomainMap {
            inner: Arc::new(iter.into_iter().collect()),
            phantom: PhantomData,
        }
    }
}

impl<K, V, S> AbstractDomain for DomainMap<K, V, S>
where
    K: PartialOrd + Ord + Clone,
    V: AbstractDomain,
    S: MapMergeStrategy<K, V> + Clone + Eq,
{
    /// Merge two `DomainMaps` according to the [`MapMergeStrategy`] of the `DomainMap`.
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            DomainMap {
                inner: Arc::new(S::merge_map(&self.inner, &other.inner)),
                phantom: PhantomData,
            }
        }
    }

    /// A `DomainMap` is considered to be a `Top` element if it is empty.
    fn is_top(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A `MapMergeStrategy` determines how the merge-method for a [`DomainMap`] works.
///
/// The possible strategies are:
/// * [`UnionMergeStrategy`]
/// * [`IntersectMergeStrategy`]
/// * [`MergeTopStrategy`]
pub trait MapMergeStrategy<K: Ord + Clone, V: AbstractDomain> {
    /// This function determines how two [`DomainMap`] instances are merged as abstract domains.
    fn merge_map(map_left: &BTreeMap<K, V>, map_right: &BTreeMap<K, V>) -> BTreeMap<K, V>;
}

/// A [`MapMergeStrategy`] where key-value pairs whose key is only present in one input map
/// are added to the merged map.
/// `Top` values and their corresponding keys are also preserved in the merged map.
///
/// The strategy is meant to be used for maps
/// where the values associated to keys not present in the map
/// have an implicit bottom value of the value abstract domain associated to them.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UnionMergeStrategy {
    _private: (), // Marker to prevent instantiation
}

impl<K: Ord + Clone, V: AbstractDomain> MapMergeStrategy<K, V> for UnionMergeStrategy {
    fn merge_map(map_left: &BTreeMap<K, V>, map_right: &BTreeMap<K, V>) -> BTreeMap<K, V> {
        let mut merged_map = map_left.clone();
        for (key, value_right) in map_right.iter() {
            merged_map
                .entry(key.clone())
                .and_modify(|value| {
                    *value = value.merge(value_right);
                })
                .or_insert_with(|| value_right.clone());
        }
        merged_map
    }
}

/// A [`MapMergeStrategy`] where the merge function only keeps keys
/// that are present in both input maps.
/// Furthermore, keys whose values are merged to the `Top` value are also removed from the merged map.
///
/// The strategy is meant to be used for maps,
/// where keys not present in the map have an implicit `Top` value associated to them.
/// The strategy implicitly assumes
/// that the `Top` value of the value abstract domain is an actual maximal value of the domain.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct IntersectMergeStrategy {
    _private: (), // Marker to prevent instantiation
}

impl<K: Ord + Clone, V: AbstractDomain> MapMergeStrategy<K, V> for IntersectMergeStrategy {
    fn merge_map(map_left: &BTreeMap<K, V>, map_right: &BTreeMap<K, V>) -> BTreeMap<K, V> {
        let mut merged_map = BTreeMap::new();
        for (key, value_left) in map_left.iter() {
            if let Some(value_right) = map_right.get(key) {
                let merged_value = value_left.merge(value_right);
                if !merged_value.is_top() {
                    merged_map.insert(key.clone(), merged_value);
                }
            }
        }
        merged_map
    }
}

/// A [`MapMergeStrategy`] where for every key that only occurs in one input map of the merge function
/// the corresponding value is merged with `Top` before being added to the merged map.
/// Furthermore, keys whose values are merged to the `Top` value are removed from the merged map.
///
/// The strategy  is an alternative to the [`IntersectMergeStrategy`]
/// in cases where the `Top` value of the value domain is not a maximal element of the abstract domain
/// and should instead be interpreted as a default element assigned to all keys not present in a domain map.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct MergeTopStrategy {
    _private: (), // Marker to prevent instantiation
}

impl<K: Ord + Clone, V: AbstractDomain + HasTop> MapMergeStrategy<K, V> for MergeTopStrategy {
    fn merge_map(map_left: &BTreeMap<K, V>, map_right: &BTreeMap<K, V>) -> BTreeMap<K, V> {
        let mut merged_map = BTreeMap::new();
        for (var, value_left) in map_left.iter() {
            let merged_value = if let Some(value_right) = map_right.get(var) {
                value_left.merge(value_right)
            } else {
                value_left.top().merge(value_left)
            };
            if !merged_value.is_top() {
                merged_map.insert(var.clone(), merged_value);
            }
        }
        for (var, value_right) in map_right.iter() {
            if map_left.get(var).is_none() {
                let merged_value = value_right.top().merge(value_right);
                if !merged_value.is_top() {
                    merged_map.insert(var.clone(), merged_value);
                }
            }
        }
        merged_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitvec;
    use std::collections::BTreeMap;

    #[test]
    fn test_merge_strategies() {
        let map_left: BTreeMap<u64, DataDomain<BitvectorDomain>> = [
            (0u64, bitvec!("0:8").into()),
            (1u64, bitvec!("0:8").into()),
            (5u64, DataDomain::new_top(ByteSize::new(8))),
        ]
        .iter()
        .cloned()
        .collect();
        let map_right: BTreeMap<u64, DataDomain<BitvectorDomain>> = [
            (1u64, bitvec!("1:8").into()),
            (2u64, bitvec!("1:8").into()),
            (5u64, DataDomain::new_top(ByteSize::new(8))),
        ]
        .iter()
        .cloned()
        .collect();

        // Test the UnionMergeStrategy.
        let domain_map_left: DomainMap<_, _, UnionMergeStrategy> = map_left.clone().into();
        let domain_map_right: DomainMap<_, _, UnionMergeStrategy> = map_right.clone().into();
        let merged_map = domain_map_left.merge(&domain_map_right);
        assert_eq!(merged_map.get(&0), Some(&bitvec!("0:8").into()));
        assert_eq!(
            merged_map.get(&1),
            Some(&BitvectorDomain::new_top(ByteSize::new(8)).into())
        );
        assert_eq!(merged_map.get(&2), Some(&bitvec!("1:8").into()));
        assert_eq!(
            merged_map.get(&5),
            Some(&DataDomain::new_top(ByteSize::new(8)).into())
        );

        // Test the IntersectMergeStrategy
        let domain_map_left: DomainMap<_, _, IntersectMergeStrategy> = map_left.clone().into();
        let domain_map_right: DomainMap<_, _, IntersectMergeStrategy> = map_right.clone().into();
        let merged_map = domain_map_left.merge(&domain_map_right);
        assert_eq!(merged_map.get(&0), None);
        assert_eq!(
            merged_map.get(&1),
            Some(&BitvectorDomain::new_top(ByteSize::new(8)).into())
        );
        assert_eq!(merged_map.get(&2), None);
        assert_eq!(merged_map.get(&5), None);

        // Test the MergeTopStrategy
        let domain_map_left: DomainMap<_, _, MergeTopStrategy> = map_left.into();
        let domain_map_right: DomainMap<_, _, MergeTopStrategy> = map_right.into();
        let merged_map = domain_map_left.merge(&domain_map_right);
        assert_eq!(
            merged_map.get(&0).unwrap().get_absolute_value(),
            Some(&bitvec!("0:8").into())
        );
        assert!(merged_map.get(&0).unwrap().contains_top());
        assert_eq!(
            merged_map.get(&1),
            Some(&BitvectorDomain::new_top(ByteSize::new(8)).into())
        );
        assert_eq!(
            merged_map.get(&2).unwrap().get_absolute_value(),
            Some(&bitvec!("1:8").into())
        );
        assert!(merged_map.get(&2).unwrap().contains_top());
        assert_eq!(merged_map.get(&5), None);
    }
}
