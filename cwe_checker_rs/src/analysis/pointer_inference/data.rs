use super::identifier::*;
use crate::analysis::abstract_domain::*;
use crate::bil::*;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

/// An abstract value representing either a pointer or a constant value.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Data {
    Top(BitSize),
    Pointer(PointerDomain),
    Value(BitvectorDomain),
}

impl Data {
    pub fn bitvector(bitv: Bitvector) -> Data {
        Data::Value(BitvectorDomain::Value(bitv))
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &BitvectorDomain,
    ) {
        if let Self::Pointer(pointer) = self {
            pointer.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
    }

    pub fn referenced_ids(&self) -> BTreeSet<AbstractIdentifier> {
        if let Self::Pointer(pointer) = self {
            pointer.0.keys().cloned().collect()
        } else {
            BTreeSet::new()
        }
    }

    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        // TODO: Some callers don't want to get Top(..) values. Probably has to be handled at the respective callsites.
        if let Data::Pointer(pointer) = self {
            let remaining_targets: BTreeMap<AbstractIdentifier, BitvectorDomain> = pointer.iter_targets().filter_map(|(id, offset)| {
                if ids_to_remove.get(id).is_none() {
                    Some((id.clone(), offset.clone()))
                } else {
                    None
                }
            }).collect();
            if remaining_targets.len() == 0 {
                *self = Data::new_top(self.bitsize());
            } else {
                *self = Data::Pointer(PointerDomain::with_targets(remaining_targets));
            }
        }
    }
}

impl Data {
    pub fn to_json_compact(&self) -> serde_json::Value {
        match self {
            Self::Top(bitsize) => serde_json::Value::String(format!("Top:{}", bitsize)),
            Self::Pointer(pointer) => {
                let target_iter = pointer.iter_targets().map(|(id, offset)| {
                    (
                        format!("{}", id),
                        serde_json::Value::String(format!("{}", offset)),
                    )
                });
                let targets = serde_json::Value::Object(target_iter.collect());
                let mut obj_map = serde_json::Map::new();
                obj_map.insert("Pointer".to_string(), targets);
                serde_json::Value::Object(obj_map)
            }
            Self::Value(bitvector) => serde_json::Value::String(format!("Value: {}", bitvector)),
        }
    }
}

impl<'a> TryFrom<&'a Data> for &'a Bitvector {
    type Error = ();

    fn try_from(value: &'a Data) -> Result<&'a Bitvector, Self::Error> {
        if let Data::Value(BitvectorDomain::Value(bitvector)) = value {
            Ok(bitvector)
        } else {
            Err(())
        }
    }
}

impl From<BitvectorDomain> for Data {
    fn from(value: BitvectorDomain) -> Data {
        Data::Value(value)
    }
}

/// An abstract value representing a pointer given as a map from an abstract identifier
/// to the offset in the pointed to object.
///
/// The map should never be empty. If the map contains more than one key,
/// it indicates that the pointer may point to any of the contained objects.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PointerDomain(BTreeMap<AbstractIdentifier, BitvectorDomain>);

impl PointerDomain {
    pub fn new(target: AbstractIdentifier, offset: BitvectorDomain) -> PointerDomain {
        let mut map = BTreeMap::new();
        map.insert(target, offset);
        PointerDomain(map)
    }

    pub fn with_targets(targets: BTreeMap<AbstractIdentifier, BitvectorDomain>) -> PointerDomain {
        PointerDomain(targets)
    }

    /// get the bitsize of the pointer
    pub fn bitsize(&self) -> BitSize {
        let some_elem = self.0.values().next().unwrap();
        some_elem.bitsize()
    }

    pub fn merge(&self, other: &PointerDomain) -> PointerDomain {
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

    /// Add a new target to the pointer.
    /// If the pointer already contains a target with the same abstract identifier, the offsets of both targets get merged.
    pub fn add_target(&mut self, target: AbstractIdentifier, offset: BitvectorDomain) {
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
        offset_adjustment: &BitvectorDomain,
    ) {
        if let Some(old_offset) = self.0.get(&old_id) {
            let new_offset = old_offset.clone() + offset_adjustment.clone();
            self.0.remove(old_id);
            self.0.insert(new_id.clone(), new_offset);
        }
    }

    /// add a value to the offset
    pub fn add_to_offset(&self, value: &BitvectorDomain) -> PointerDomain {
        let mut result = self.clone();
        for offset in result.0.values_mut() {
            *offset = offset.bin_op(BinOpType::PLUS, value);
        }
        result
    }

    /// subtract a value from the offset
    pub fn sub_from_offset(&self, value: &BitvectorDomain) -> PointerDomain {
        let mut result = self.clone();
        for offset in result.0.values_mut() {
            *offset = offset.bin_op(BinOpType::MINUS, value);
        }
        result
    }

    /// Get an iterator over all possible abstract targets (together with the offset in the target) the pointer may point to.
    pub fn iter_targets(
        &self,
    ) -> std::collections::btree_map::Iter<AbstractIdentifier, BitvectorDomain> {
        self.0.iter()
    }

    pub fn get_target_ids(&self) -> BTreeSet<AbstractIdentifier> {
        self.0.keys().cloned().collect()
    }
}

impl PointerDomain {
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

impl ValueDomain for Data {
    fn bitsize(&self) -> BitSize {
        use Data::*;
        match self {
            Top(size) => *size,
            Pointer(pointer) => pointer.bitsize(),
            Value(bitvec) => bitvec.bitsize(),
        }
    }

    fn new_top(bitsize: BitSize) -> Data {
        Data::Top(bitsize)
    }

    /// Compute the (abstract) result of a binary operation
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        use Data::*;
        match (self, op, rhs) {
            (Value(left), _, Value(right)) => Value(left.bin_op(op, right)),
            (Pointer(pointer), PLUS, Value(value)) | (Value(value), PLUS, Pointer(pointer)) => {
                Pointer(pointer.add_to_offset(value))
            }
            (Pointer(pointer), MINUS, Value(value)) => Pointer(pointer.sub_from_offset(value)),
            // TODO: AND and OR binops may be used to compute pointers when alignment information about the pointer is known.
            (_, EQ, _) | (_, NEQ, _) | (_, LT, _) | (_, LE, _) | (_, SLT, _) | (_, SLE, _) => {
                BitvectorDomain::new_top(1).into()
            }
            (_, PLUS, _)
            | (_, MINUS, _)
            | (_, TIMES, _)
            | (_, DIVIDE, _)
            | (_, SDIVIDE, _)
            | (_, MOD, _)
            | (_, SMOD, _)
            | (_, LSHIFT, _)
            | (_, RSHIFT, _)
            | (_, ARSHIFT, _)
            | (_, AND, _)
            | (_, OR, _)
            | (_, XOR, _) => Data::new_top(self.bitsize()),
        }
    }

    /// Compute the (abstract) result of a unary operation
    fn un_op(&self, op: UnOpType) -> Self {
        if let Data::Value(value) = self {
            Data::Value(value.un_op(op))
        } else {
            Data::new_top(self.bitsize())
        }
    }

    /// extract a sub-bitvector
    fn extract(&self, low_bit: BitSize, high_bit: BitSize) -> Self {
        if let Data::Value(value) = self {
            Data::Value(value.extract(low_bit, high_bit))
        } else {
            Data::new_top(high_bit - low_bit + 1)
        }
    }

    /// Extend a bitvector using the given cast type
    fn cast(&self, kind: CastType, width: BitSize) -> Self {
        if self.bitsize() == width {
            // The cast is a no-op.
            return self.clone();
        }
        if let Data::Value(value) = self {
            Data::Value(value.cast(kind, width))
        } else {
            Data::new_top(width)
        }
    }

    /// Concatenate two bitvectors
    fn concat(&self, other: &Self) -> Self {
        if let (Data::Value(upper_bits), Data::Value(lower_bits)) = (self, other) {
            Data::Value(upper_bits.concat(lower_bits))
        } else {
            Data::new_top(self.bitsize() + other.bitsize())
        }
    }
}

impl AbstractDomain for Data {
    fn top(&self) -> Self {
        Data::Top(self.bitsize())
    }

    fn merge(&self, other: &Self) -> Self {
        use Data::*;
        match (self, other) {
            (Top(bitsize), _) | (_, Top(bitsize)) => Top(*bitsize),
            (Pointer(pointer1), Pointer(pointer2)) => Pointer(pointer1.merge(pointer2)),
            (Value(val1), Value(val2)) => Value(val1.merge(val2)),
            (Pointer(_), Value(_)) | (Value(_), Pointer(_)) => Top(self.bitsize()),
        }
    }

    /// Return whether the element represents a top element or not.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top(_))
    }
}

impl From<PointerDomain> for Data {
    fn from(val: PointerDomain) -> Data {
        Data::Pointer(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: String) -> AbstractIdentifier {
        AbstractIdentifier::new(Tid::new("time0"), AbstractLocation::Register(name, 64))
    }

    fn new_pointer_domain(location: String, offset: i64) -> PointerDomain {
        let id = new_id(location);
        PointerDomain::new(id, bv(offset))
    }

    fn new_pointer(location: String, offset: i64) -> Data {
        Data::Pointer(new_pointer_domain(location, offset))
    }

    fn new_value(value: i64) -> Data {
        Data::Value(bv(value))
    }

    #[test]
    fn data_abstract_domain() {
        let pointer = new_pointer("Rax".into(), 0);
        let data = new_value(42);
        assert_eq!(pointer.merge(&pointer), pointer);
        assert_eq!(pointer.merge(&data), Data::new_top(64));
        assert_eq!(
            data.merge(&new_value(41)),
            Data::Value(BitvectorDomain::new_top(64))
        );

        let other_pointer = new_pointer("Rbx".into(), 0);
        match pointer.merge(&other_pointer) {
            Data::Pointer(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn data_value_domain() {
        use crate::bil::BinOpType::*;
        let data = new_value(42);
        assert_eq!(data.bitsize(), 64);

        let three = new_value(3);
        let pointer = new_pointer("Rax".into(), 0);
        assert_eq!(data.bin_op(PLUS, &three), new_value(45));
        assert_eq!(pointer.bin_op(PLUS, &three), new_pointer("Rax".into(), 3));
        assert_eq!(three.un_op(crate::bil::UnOpType::NEG), new_value(-3));

        assert_eq!(
            three.extract(0, 31),
            Data::Value(BitvectorDomain::Value(Bitvector::from_i32(3)))
        );

        assert_eq!(data.cast(crate::bil::CastType::SIGNED, 128).bitsize(), 128);

        let one = Data::Value(BitvectorDomain::Value(Bitvector::from_i32(1)));
        let two = Data::Value(BitvectorDomain::Value(Bitvector::from_i32(2)));
        let concat = new_value((1 << 32) + 2);
        assert_eq!(one.concat(&two), concat);
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
}
