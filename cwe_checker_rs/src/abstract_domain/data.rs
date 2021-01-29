use super::{
    AbstractDomain, AbstractIdentifier, HasTop, PointerDomain, RegisterDomain, SizedDomain,
};
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

/// An abstract domain representing either a pointer or a non-pointer value.
/// Both non-pointer values and offsets of pointers are represented by the same abstract domain `T`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DataDomain<T: RegisterDomain> {
    Top(ByteSize),
    Pointer(PointerDomain<T>),
    Value(T),
}

impl<T: RegisterDomain> DataDomain<T> {
    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &T,
    ) {
        if let Self::Pointer(pointer) = self {
            pointer.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
    }

    /// Return a set of all referenced abstract IDs. The set is empty if `self` is not a pointer.
    pub fn referenced_ids(&self) -> BTreeSet<AbstractIdentifier> {
        if let Self::Pointer(pointer) = self {
            pointer.ids().cloned().collect()
        } else {
            BTreeSet::new()
        }
    }

    /// If *self* is a pointer, remove all provided IDs from the target list of it.
    /// If this would leave the pointer without any targets, replace it with *Top*.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        if let Self::Pointer(pointer) = self {
            let remaining_targets: BTreeMap<AbstractIdentifier, T> = pointer
                .targets()
                .iter()
                .filter_map(|(id, offset)| {
                    if ids_to_remove.get(id).is_none() {
                        Some((id.clone(), offset.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if remaining_targets.is_empty() {
                *self = Self::new_top(self.bytesize());
            } else {
                *self = Self::Pointer(PointerDomain::with_targets(remaining_targets));
            }
        }
    }
}

impl<T: RegisterDomain> SizedDomain for DataDomain<T> {
    // Return the bitsize of `self`.
    fn bytesize(&self) -> ByteSize {
        use DataDomain::*;
        match self {
            Top(size) => *size,
            Pointer(pointer) => pointer.bytesize(),
            Value(bitvec) => bitvec.bytesize(),
        }
    }

    // Return a new *Top* element with the given bytesize
    fn new_top(bytesize: ByteSize) -> Self {
        Self::Top(bytesize)
    }
}

impl<T: RegisterDomain> HasTop for DataDomain<T> {
    // Generate a new *Top* element with the same bitsize as `self`.
    fn top(&self) -> Self {
        DataDomain::new_top(self.bytesize())
    }
}

impl<T: RegisterDomain> RegisterDomain for DataDomain<T> {
    /// Compute the (abstract) result of a binary operation
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        use DataDomain::*;
        match (self, op, rhs) {
            (Value(left), _, Value(right)) => Value(left.bin_op(op, right)),
            (Pointer(pointer), IntAdd, Value(value)) | (Value(value), IntAdd, Pointer(pointer)) => {
                Pointer(pointer.add_to_offset(value))
            }
            (Pointer(pointer), IntSub, Value(value)) => Pointer(pointer.sub_from_offset(value)),
            (Pointer(pointer_lhs), IntSub, Pointer(pointer_rhs)) => {
                if pointer_lhs.ids().len() == 1 && pointer_rhs.ids().len() == 1 {
                    let (id_lhs, offset_lhs) = pointer_lhs.targets().iter().next().unwrap();
                    let (id_rhs, offset_rhs) = pointer_rhs.targets().iter().next().unwrap();
                    if id_lhs == id_rhs {
                        Self::Value(offset_lhs.bin_op(IntSub, offset_rhs))
                    } else {
                        Self::Top(self.bytesize())
                    }
                } else {
                    // We cannot be sure that both pointers point to the same target
                    Self::Top(self.bytesize())
                }
            }
            (_, IntEqual, _)
            | (_, IntNotEqual, _)
            | (_, IntLess, _)
            | (_, IntLessEqual, _)
            | (_, IntSLess, _)
            | (_, IntSLessEqual, _)
            | (_, IntCarry, _)
            | (_, IntSCarry, _)
            | (_, IntSBorrow, _)
            | (_, BoolXOr, _)
            | (_, BoolOr, _)
            | (_, BoolAnd, _)
            | (_, FloatEqual, _)
            | (_, FloatNotEqual, _)
            | (_, FloatLess, _)
            | (_, FloatLessEqual, _) => T::new_top(ByteSize::new(1)).into(),
            (_, IntAdd, _)
            | (_, IntSub, _)
            | (_, IntMult, _)
            | (_, IntDiv, _)
            | (_, IntSDiv, _)
            | (_, IntRem, _)
            | (_, IntSRem, _)
            | (_, IntLeft, _)
            | (_, IntRight, _)
            | (_, IntSRight, _)
            | (_, IntAnd, _)
            | (_, IntOr, _)
            | (_, IntXOr, _)
            | (_, FloatAdd, _)
            | (_, FloatSub, _)
            | (_, FloatMult, _)
            | (_, FloatDiv, _) => Self::new_top(self.bytesize()),
            (_, Piece, _) => Self::new_top(self.bytesize() + rhs.bytesize()),
        }
    }

    /// Compute the (abstract) result of a unary operation
    fn un_op(&self, op: UnOpType) -> Self {
        if let Self::Value(value) = self {
            Self::Value(value.un_op(op))
        } else {
            Self::new_top(self.bytesize())
        }
    }

    /// extract a sub-bitvector
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        if let Self::Value(value) = self {
            Self::Value(value.subpiece(low_byte, size))
        } else if low_byte == ByteSize::new(0) && size == self.bytesize() {
            // The operation is a no-op
            self.clone()
        } else {
            Self::new_top(size)
        }
    }

    /// Cast a bitvector using the given cast type
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self {
        if let Self::Value(value) = self {
            Self::Value(value.cast(kind, width))
        } else {
            // The result of casting pointers is undefined.
            Self::new_top(width)
        }
    }
}

impl<T: RegisterDomain> AbstractDomain for DataDomain<T> {
    // Merge `self` with `other`.
    fn merge(&self, other: &Self) -> Self {
        use DataDomain::*;
        match (self, other) {
            (Top(bytesize), _) | (_, Top(bytesize)) => Top(*bytesize),
            (Pointer(pointer1), Pointer(pointer2)) => Pointer(pointer1.merge(pointer2)),
            (Value(val1), Value(val2)) => Value(val1.merge(val2)),
            (Pointer(_), Value(_)) | (Value(_), Pointer(_)) => Top(self.bytesize()),
        }
    }

    /// Return whether the element represents a top element or not.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top(_))
    }
}

impl<T: RegisterDomain> From<PointerDomain<T>> for DataDomain<T> {
    fn from(val: PointerDomain<T>) -> Self {
        Self::Pointer(val)
    }
}

impl<T: RegisterDomain> From<T> for DataDomain<T> {
    fn from(value: T) -> Self {
        Self::Value(value)
    }
}

impl<T: RegisterDomain + From<Bitvector>> From<Bitvector> for DataDomain<T> {
    fn from(bitvector: Bitvector) -> Self {
        Self::Value(bitvector.into())
    }
}

impl<T: RegisterDomain + Display> DataDomain<T> {
    /// Get a more compact json-representation of the data domain.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        match self {
            Self::Top(bitsize) => serde_json::Value::String(format!("Top:{}", bitsize)),
            Self::Pointer(pointer) => {
                let target_iter = pointer.targets().iter().map(|(id, offset)| {
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

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    type Data = DataDomain<BitvectorDomain>;

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

    fn new_pointer(location: &str, offset: i64) -> Data {
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
        assert_eq!(pointer.merge(&data), Data::new_top(ByteSize::new(8)));
        assert_eq!(
            data.merge(&new_value(41)),
            Data::Value(BitvectorDomain::new_top(ByteSize::new(8)))
        );

        let other_pointer = new_pointer("Rbx".into(), 0);
        match pointer.merge(&other_pointer) {
            Data::Pointer(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn data_register_domain() {
        use BinOpType::*;
        let data = new_value(42);
        assert_eq!(data.bytesize(), ByteSize::new(8));

        let three = new_value(3);
        let pointer = new_pointer("Rax".into(), 0);
        assert_eq!(data.bin_op(IntAdd, &three), new_value(45));
        assert_eq!(pointer.bin_op(IntAdd, &three), new_pointer("Rax".into(), 3));
        assert_eq!(three.un_op(UnOpType::Int2Comp), new_value(-3));

        assert_eq!(
            three.subpiece(ByteSize::new(0), ByteSize::new(4)),
            Data::Value(BitvectorDomain::Value(Bitvector::from_i32(3)))
        );

        assert_eq!(
            data.cast(CastOpType::IntSExt, ByteSize::new(16)).bytesize(),
            ByteSize::new(16)
        );

        let one = Data::Value(BitvectorDomain::Value(Bitvector::from_i32(1)));
        let two = Data::Value(BitvectorDomain::Value(Bitvector::from_i32(2)));
        let concat = new_value((1 << 32) + 2);
        assert_eq!(one.bin_op(Piece, &two), concat);
    }

    #[test]
    fn remove_ids() {
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), bv(1));
        targets.insert(new_id("Rbx"), bv(2));
        let mut data: Data = PointerDomain::with_targets(targets).into();

        let mut ids_to_remove = BTreeSet::new();
        ids_to_remove.insert(new_id("Rbx"));
        ids_to_remove.insert(new_id("Rcx"));

        data.remove_ids(&ids_to_remove);
        assert_eq!(
            data.referenced_ids(),
            vec![new_id("Rax")].into_iter().collect()
        );

        data = bv(42).into();
        data.remove_ids(&ids_to_remove);
        assert_eq!(data, bv(42).into());
    }
}
