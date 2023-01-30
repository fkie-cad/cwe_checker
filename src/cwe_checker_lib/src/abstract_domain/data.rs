use super::{
    AbstractDomain, AbstractIdentifier, HasTop, Interval, RegisterDomain, SizedDomain,
    SpecializeByConditional, TryToBitvec, TryToInterval,
};
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::iter::FromIterator;

mod arithmetics;
mod conditional_specialization;
mod trait_impl;

/// An abstract domain representing a set of base values plus offsets or an absolute value (or both).
///
/// The base values are represented as abstract IDs,
/// i.e. they are treated as variables with unknown absolute value, e.g. the returned pointer by malloc.
/// For each base value the offset is given by an abstract domain `T`,
/// which should specialize in representing absolute values (e.g. an interval domain).
/// Note that the domain assumes pointer semantics for these values.
/// That means if one applies operations to the domain that are not used in pointer arithmetics,
/// the abstract ID of the base value might be removed from the domain.
///
/// If the domain also represents absolute values,
/// then the values are given by a single instance of the abstract domain `T`.
///
/// The domain also contains a flag to indicate that it includes `Top` values,
/// i.e. values of fully unknown origin and offset.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DataDomain<T: RegisterDomain> {
    /// The byte size of the represented values.
    size: ByteSize,
    /// A map from base values to the corresponding offset.
    relative_values: BTreeMap<AbstractIdentifier, T>,
    /// An absolute value if the domain may represent an absolute value.
    absolute_value: Option<T>,
    /// An indicator whether the domain also represents values for which both the base and the offset are unknown.
    contains_top_values: bool,
}

impl<T: RegisterDomain> DataDomain<T> {
    /// Returns true if the domain does not represent any value.
    ///
    /// The meaning of an empty value depends on the usage of the domain.
    /// E.g. it may indicate an impossible runtime state of a program in one analysis
    /// or simply no value of interest in another analysis.
    ///
    /// An empty value represents the bottom value in the partial order of the domain.
    pub fn is_empty(&self) -> bool {
        self.relative_values.is_empty()
            && self.absolute_value.is_none()
            && !self.contains_top_values
    }

    /// Return a new empty value with the given bytesize.
    pub fn new_empty(size: ByteSize) -> Self {
        DataDomain {
            size,
            relative_values: BTreeMap::new(),
            absolute_value: None,
            contains_top_values: false,
        }
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &T,
    ) {
        if let Some(old_offset) = self.relative_values.get(old_id) {
            let new_offset = old_offset.bin_op(BinOpType::IntAdd, offset_adjustment);
            self.relative_values.remove(old_id);
            self.relative_values.insert(new_id.clone(), new_offset);
        }
    }

    /// Replace all abstract IDs in self with the corresponding values given by the `replacement_map`.
    ///
    /// For IDs without a replacement value the `contains_top_values` flag will be set.
    pub fn replace_all_ids(&mut self, replacement_map: &BTreeMap<AbstractIdentifier, Self>) {
        let mut new_self = DataDomain {
            size: self.size,
            relative_values: BTreeMap::new(),
            absolute_value: self.absolute_value.clone(),
            contains_top_values: self.contains_top_values,
        };
        for (id, offset) in self.relative_values.iter() {
            if let Some(replacement_value) = replacement_map.get(id) {
                new_self = new_self.merge(&(replacement_value.clone() + offset.clone().into()));
            } else {
                new_self.contains_top_values = true;
            }
        }
        *self = new_self;
    }

    /// Return an iterator over all referenced abstract IDs.
    pub fn referenced_ids(&self) -> impl Iterator<Item = &AbstractIdentifier> {
        self.relative_values.keys()
    }

    /// Return the relative values contained in the domain.
    pub fn get_relative_values(&self) -> &BTreeMap<AbstractIdentifier, T> {
        &self.relative_values
    }

    /// Replace the map of relative values with the given one.
    pub fn set_relative_values(&mut self, relative_values: BTreeMap<AbstractIdentifier, T>) {
        self.relative_values = relative_values;
    }

    /// Return the absolute value contained in the domain if present
    pub fn get_absolute_value(&self) -> Option<&T> {
        self.absolute_value.as_ref()
    }

    /// Replace the absolute value contained in the domain with the given one.
    /// A value of `None` means that the domain does not contain an absolute value.
    pub fn set_absolute_value(&mut self, value: Option<T>) {
        self.absolute_value = value
    }

    /// Returns `true` if the domain contains `Top` values,
    /// i.e. values for which neither a value nor an abstract identifier is known.
    ///
    /// Note that the `DataDomain` itself has no maximal value,
    /// i.e. this does not indicate a `Top` value of the abstract domain.
    pub fn contains_top(&self) -> bool {
        self.contains_top_values
    }

    /// Indicate that the domain may contain `Top` values
    /// in addition to the contained absolute and relative values.
    ///
    /// This does not remove absolute or relative value information from the domain.
    pub fn set_contains_top_flag(&mut self) {
        self.contains_top_values = true;
    }

    /// Indicate that the domain does not contain any `Top` values
    /// in addition to the contained absolute and relative values.
    pub fn unset_contains_top_flag(&mut self) {
        self.contains_top_values = false;
    }

    /// Return a new value representing a variable plus an offset,
    /// where the variable is represented by the given abstract ID.
    pub fn from_target(id: AbstractIdentifier, offset: T) -> Self {
        DataDomain {
            size: offset.bytesize(),
            relative_values: BTreeMap::from_iter([(id, offset)]),
            absolute_value: None,
            contains_top_values: false,
        }
    }

    /// Remove all provided IDs from the list of relative values.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        self.relative_values = self
            .relative_values
            .iter()
            .filter_map(|(id, offset)| {
                if ids_to_remove.get(id).is_none() {
                    Some((id.clone(), offset.clone()))
                } else {
                    None
                }
            })
            .collect();
    }

    /// Return the contained absolute value
    /// only if `self` contains no other (relative or `Top`) values.
    pub fn get_if_absolute_value(&self) -> Option<&T> {
        if self.relative_values.is_empty() && !self.contains_top_values {
            self.absolute_value.as_ref()
        } else {
            None
        }
    }

    /// Return the contained absolute value
    /// if `self` only contains absolute or `Top` values.
    fn get_if_absolute_value_or_top(&self) -> Option<&T> {
        if self.relative_values.is_empty() {
            self.absolute_value.as_ref()
        } else {
            None
        }
    }

    /// Return the target ID and offset of the contained relative value
    /// if `self` contains exactly one relative value and no absolute or `Top` values.
    pub fn get_if_unique_target(&self) -> Option<(&AbstractIdentifier, &T)> {
        if self.relative_values.len() == 1
            && self.absolute_value.is_none()
            && !self.contains_top_values
        {
            Some(self.relative_values.iter().next().unwrap())
        } else {
            None
        }
    }
}

impl<T: RegisterDomain + Display> DataDomain<T> {
    /// Get a more compact json-representation of the data domain.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut values = Vec::new();
        if !self.relative_values.is_empty() {
            let target_iter = self.relative_values.iter().map(|(id, offset)| {
                (
                    format!("{id}"),
                    serde_json::Value::String(format!("{offset}")),
                )
            });
            let targets = serde_json::Value::Object(target_iter.collect());
            let mut obj_map = serde_json::Map::new();
            obj_map.insert("Pointer".to_string(), targets);
            values.push(serde_json::Value::Object(obj_map));
        }
        if let Some(absolute_value) = &self.absolute_value {
            values.push(serde_json::Value::String(format!(
                "Value: {absolute_value}"
            )));
        }
        if self.contains_top_values {
            values.push(serde_json::Value::String(format!(
                "Top:i{}",
                self.bytesize().as_bit_length()
            )));
        }
        match values.len() {
            0 => serde_json::Value::String(format!("Empty:{}", self.bytesize())),
            1 => values.pop().unwrap(),
            _ => serde_json::Value::Array(values),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::{bitvec, variable};

    impl<T: RegisterDomain> DataDomain<T> {
        /// Return a new domain representing a set of relative values.
        /// Note that this function will panic if given an empty set as input.
        pub fn mock_from_target_map(targets: BTreeMap<AbstractIdentifier, T>) -> Self {
            DataDomain {
                size: targets.values().next().unwrap().bytesize(),
                relative_values: targets,
                absolute_value: None,
                contains_top_values: false,
            }
        }

        pub fn insert_relative_value(&mut self, id: AbstractIdentifier, offset: T) {
            self.relative_values.insert(id, offset);
        }
    }

    fn bv(value: i64) -> BitvectorDomain {
        bitvec!(format!("{}:8", value)).into()
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(variable!(format!("{}:8", name))),
        )
    }

    #[test]
    fn replace_abstract_ids() {
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), bv(1));
        targets.insert(new_id("Rbx"), bv(2));
        targets.insert(new_id("Rcx"), bv(3));
        // Test replacing exactly one ID.
        let mut data = DataDomain::mock_from_target_map(targets.clone());
        data.replace_abstract_id(&new_id("Rbx"), &new_id("replaced_Rbx"), &bv(10));
        assert_eq!(data.relative_values.len(), 3);
        assert_eq!(*data.relative_values.get(&new_id("Rax")).unwrap(), bv(1));
        assert_eq!(
            *data.relative_values.get(&new_id("replaced_Rbx")).unwrap(),
            bv(12)
        );
        // Test replacing all IDs using a replacement map.
        let mut data = DataDomain::mock_from_target_map(targets);
        let replacement_map = BTreeMap::from_iter([
            (
                new_id("Rax"),
                DataDomain::from_target(new_id("replaced_Rax"), bv(0)),
            ),
            (new_id("Rbx"), bv(10).into()),
        ]);
        data.replace_all_ids(&replacement_map);
        assert_eq!(data.relative_values.len(), 1);
        assert_eq!(
            *data.relative_values.get(&new_id("replaced_Rax")).unwrap(),
            bv(1)
        );
        assert!(data.contains_top());
        assert_eq!(data.absolute_value.unwrap(), bv(12));
    }

    #[test]
    fn remove_ids() {
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), bv(1));
        targets.insert(new_id("Rbx"), bv(2));
        let mut data = DataDomain::mock_from_target_map(targets);

        let mut ids_to_remove = BTreeSet::new();
        ids_to_remove.insert(new_id("Rbx"));
        ids_to_remove.insert(new_id("Rcx"));

        data.remove_ids(&ids_to_remove);
        assert_eq!(
            data.referenced_ids()
                .cloned()
                .collect::<Vec<AbstractIdentifier>>(),
            vec![new_id("Rax")]
        );

        data = bv(42).into();
        data.remove_ids(&ids_to_remove);
        assert_eq!(data, bv(42).into());
    }
}
