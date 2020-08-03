use crate::abstract_domain::*;
use crate::bil::*;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

/// An abstract value representing either a pointer or a constant value.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Data {
    Top(BitSize),
    Pointer(PointerDomain<BitvectorDomain>),
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
            pointer.ids().cloned().collect()
        } else {
            BTreeSet::new()
        }
    }

    /// If *self* is a pointer, remove all provided IDs from the target list of it.
    /// If this would leave the pointer without any targets, replace it with Data::Top(..).
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        // TODO: Some callers don't want to get Top(..) values. Probably has to be handled at the respective callsites.
        if let Data::Pointer(pointer) = self {
            let remaining_targets: BTreeMap<AbstractIdentifier, BitvectorDomain> = pointer
                .iter_targets()
                .filter_map(|(id, offset)| {
                    if ids_to_remove.get(id).is_none() {
                        Some((id.clone(), offset.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if remaining_targets.is_empty() {
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

impl HasBitSize for Data {
    fn bitsize(&self) -> BitSize {
        use Data::*;
        match self {
            Top(size) => *size,
            Pointer(pointer) => pointer.bitsize(),
            Value(bitvec) => bitvec.bitsize(),
        }
    }
}

impl HasTop for Data {
    fn top(&self) -> Self {
        Data::new_top(self.bitsize())
    }
}

impl RegisterDomain for Data {
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

impl From<PointerDomain<BitvectorDomain>> for Data {
    fn from(val: PointerDomain<BitvectorDomain>) -> Data {
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

    fn new_pointer_domain(location: String, offset: i64) -> PointerDomain<BitvectorDomain> {
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
}
