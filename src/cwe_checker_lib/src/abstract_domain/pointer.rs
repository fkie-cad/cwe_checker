use super::{AbstractDomain, AbstractIdentifier, RegisterDomain, SizedDomain};
use crate::intermediate_representation::{BinOpType, ByteSize};
use crate::prelude::*;
use std::collections::BTreeMap;
use std::fmt::Display;

/// An abstract value representing a pointer given as a map from an abstract identifier
/// to the offset in the pointed to object. The offset itself is also a member of an abstract domain.
///
/// If the map contains more than one key,
/// it indicates that the pointer may point to any of the contained objects.
///
/// A `PointerDomain` value always has at least one target.
/// Trying to create a pointer without targets should always lead to panics.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PointerDomain<T: RegisterDomain>(BTreeMap<AbstractIdentifier, T>);

impl<T: RegisterDomain> AbstractDomain for PointerDomain<T> {
    /// Merge two pointers.
    ///
    /// The merged pointer contains all targets of `self` and `other`.
    /// For targets, that are contained in both, the offsets are merged.
    fn merge(&self, other: &Self) -> Self {
        let mut merged_map = self.0.clone();
        for (location, offset) in other.0.iter() {
            if merged_map.contains_key(location) {
                merged_map.insert(location.clone(), merged_map[location].merge(offset));
            } else {
                merged_map.insert(location.clone(), offset.clone());
            }
        }
        PointerDomain(merged_map)
    }

    /// Returns false, as PointerDomain has no *Top* element.
    fn is_top(&self) -> bool {
        false
    }
}

impl<T: RegisterDomain> SizedDomain for PointerDomain<T> {
    /// Return the bitsize of the pointer.
    /// Should always equal the pointer size of the CPU architecture.
    fn bytesize(&self) -> ByteSize {
        self.0
            .values()
            .next()
            .expect("Pointer without targets encountered")
            .bytesize()
    }

    /// PointerDomain has no explicit `Top` element, thus calling this function will panic.
    fn new_top(_bytesize: ByteSize) -> Self {
        panic!()
    }
}

impl<T: RegisterDomain> PointerDomain<T> {
    /// Create a new pointer with exactly one target.
    pub fn new(target: AbstractIdentifier, offset: T) -> PointerDomain<T> {
        let mut map = BTreeMap::new();
        map.insert(target, offset);
        PointerDomain(map)
    }

    /// Create a new pointer with a set of targets. Panics if no targets are provided.
    pub fn with_targets(targets: BTreeMap<AbstractIdentifier, T>) -> PointerDomain<T> {
        assert!(!targets.is_empty());
        PointerDomain(targets)
    }

    /// Add a new target to the pointer.
    /// If the pointer already contains a target with the same abstract identifier, the offsets of both targets get merged.
    pub fn add_target(&mut self, target: AbstractIdentifier, offset: T) {
        if let Some(old_offset) = self.0.get(&target) {
            let merged_offset = old_offset.merge(&offset);
            self.0.insert(target, merged_offset);
        } else {
            self.0.insert(target, offset);
        }
    }

    /// Replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &T,
    ) {
        if let Some(old_offset) = self.0.get(&old_id) {
            let new_offset = old_offset.bin_op(BinOpType::IntAdd, offset_adjustment);
            self.0.remove(old_id);
            self.0.insert(new_id.clone(), new_offset);
        }
    }

    /// add a value to the offset
    pub fn add_to_offset(&self, value: &T) -> PointerDomain<T> {
        let mut result = self.clone();
        for offset in result.0.values_mut() {
            *offset = offset.bin_op(BinOpType::IntAdd, value);
        }
        result
    }

    /// subtract a value from the offset
    pub fn sub_from_offset(&self, value: &T) -> PointerDomain<T> {
        let mut result = self.clone();
        for offset in result.0.values_mut() {
            *offset = offset.bin_op(BinOpType::IntSub, value);
        }
        result
    }

    /// Get all possible abstract targets (together with the offset in the target) the pointer may point to.
    pub fn targets(&self) -> &BTreeMap<AbstractIdentifier, T> {
        &self.0
    }

    /// Get an iterator over all abstract IDs that the pointer may target.
    pub fn ids(&self) -> std::collections::btree_map::Keys<AbstractIdentifier, T> {
        self.0.keys()
    }

    /// Return the target and offset of the pointer if it points to an unique ID.
    pub fn unwrap_if_unique_target(&self) -> Option<(&AbstractIdentifier, &T)> {
        if self.0.len() == 1 {
            return self.0.iter().next();
        } else {
            None
        }
    }
}

impl<T: RegisterDomain + Display> PointerDomain<T> {
    /// Get a more compact json-representation of the pointer.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.0
                .iter()
                .map(|(id, offset)| {
                    (
                        format!("{}", id),
                        serde_json::Value::String(format!("{}", offset)),
                    )
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AbstractLocation, BitvectorDomain};
    use super::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(name.into(), ByteSize::new(8)),
        )
    }

    fn new_pointer_domain(location: &str, offset: i64) -> PointerDomain<BitvectorDomain> {
        let id = new_id(location);
        PointerDomain::new(id, bv(offset))
    }

    #[test]
    fn pointer_domain() {
        let pointer = new_pointer_domain("Rax".into(), 0);
        let offset = bv(3);

        let pointer_plus = new_pointer_domain("Rax".into(), 3);
        let pointer_minus = new_pointer_domain("Rax".into(), -3);
        assert_eq!(pointer.add_to_offset(&offset), pointer_plus);
        assert_eq!(pointer.sub_from_offset(&offset), pointer_minus);

        let other_pointer = new_pointer_domain("Rbx".into(), 5);
        let merged = pointer.merge(&other_pointer);
        assert_eq!(merged.0.len(), 2);
        assert_eq!(merged.0.get(&new_id("Rax".into())), Some(&bv(0)));
        assert_eq!(merged.0.get(&new_id("Rbx".into())), Some(&bv(5)));
    }

    #[test]
    fn replace_abstract_id() {
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), bv(5));
        targets.insert(new_id("Rbx"), bv(7));
        let mut pointer = PointerDomain::with_targets(targets);

        pointer.replace_abstract_id(&new_id("Rax"), &new_id("replacement"), &bv(5));
        let mut new_targets = BTreeMap::new();
        new_targets.insert(new_id("replacement"), bv(10));
        new_targets.insert(new_id("Rbx"), bv(7));

        assert_eq!(pointer.0, new_targets);
    }
}
