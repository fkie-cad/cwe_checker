use super::Interval;
use super::{AbstractDomain, HasTop, RegisterDomain, SizedDomain, TryToBitvec, TryToInterval};
use crate::intermediate_representation::*;
use crate::prelude::*;

/// The `BitvectorDomain` is a simple abstract domain describing a bitvector of known length.
///
/// As values it can only assume a known bitvector or *Top(bytesize)*.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum BitvectorDomain {
    /// The `Top` value of the domain, representing the case that nothing is known about the actual value.
    Top(ByteSize),
    /// The exact value of the bitvector is known.
    Value(Bitvector),
}

impl AbstractDomain for BitvectorDomain {
    /// merge two values. Returns *Top* if the values are not equal.
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            self.top()
        }
    }

    /// Check if the value is *Top*.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top(_))
    }
}

impl HasTop for BitvectorDomain {
    /// Return a *Top* value with the same bytesize as `self`.
    fn top(&self) -> BitvectorDomain {
        BitvectorDomain::Top(self.bytesize())
    }
}

impl SizedDomain for BitvectorDomain {
    /// Return the bytesize of `self`.
    fn bytesize(&self) -> ByteSize {
        use BitvectorDomain::*;
        match self {
            Top(bytesize) => *bytesize,
            Value(bitvec) => bitvec.width().into(),
        }
    }

    /// Get a *Top* element with the given bitsize.
    fn new_top(bytesize: ByteSize) -> BitvectorDomain {
        BitvectorDomain::Top(bytesize)
    }
}

impl RegisterDomain for BitvectorDomain {
    /// Evaluate the given binary operation.
    ///
    /// For non-shift operations, this function will panic if the operands have different bitsizes.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        match op {
            Piece | IntLeft | IntRight | IntSRight => (),
            _ => assert_eq!(self.bytesize(), rhs.bytesize()),
        }
        match (self, rhs) {
            (BitvectorDomain::Value(lhs_bitvec), BitvectorDomain::Value(rhs_bitvec)) => {
                match lhs_bitvec.bin_op(op, rhs_bitvec) {
                    Ok(val) => BitvectorDomain::Value(val),
                    Err(_) => BitvectorDomain::new_top(self.bin_op_bytesize(op, rhs)),
                }
            }
            _ => BitvectorDomain::new_top(self.bin_op_bytesize(op, rhs)),
        }
    }

    /// Evaluate the given unary operation.
    fn un_op(&self, op: UnOpType) -> Self {
        use UnOpType::*;
        if let BitvectorDomain::Value(bitvec) = self {
            match bitvec.un_op(op) {
                Ok(val) => BitvectorDomain::Value(val),
                Err(_) => match op {
                    BoolNegate | FloatNaN => BitvectorDomain::new_top(ByteSize::new(1)),
                    _ => BitvectorDomain::new_top(self.bytesize()),
                },
            }
        } else {
            match op {
                BoolNegate | FloatNaN => BitvectorDomain::new_top(ByteSize::new(1)),
                _ => BitvectorDomain::new_top(self.bytesize()),
            }
        }
    }

    /// Extract a sub-bitvector out of a bitvector
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            BitvectorDomain::Value(bitvec.subpiece(low_byte, size))
        } else {
            BitvectorDomain::new_top(size)
        }
    }

    /// Perform a size-changing cast on a bitvector.
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            match bitvec.cast(kind, width) {
                Ok(val) => BitvectorDomain::Value(val),
                Err(_) => BitvectorDomain::new_top(width),
            }
        } else {
            BitvectorDomain::new_top(width)
        }
    }
}

impl std::ops::Add for BitvectorDomain {
    type Output = BitvectorDomain;

    fn add(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntAdd, &rhs)
    }
}

impl std::ops::Sub for BitvectorDomain {
    type Output = BitvectorDomain;

    fn sub(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntSub, &rhs)
    }
}

impl std::ops::Neg for BitvectorDomain {
    type Output = BitvectorDomain;

    fn neg(self) -> Self {
        self.un_op(UnOpType::Int2Comp)
    }
}

impl std::convert::From<Bitvector> for BitvectorDomain {
    fn from(bitvector: Bitvector) -> BitvectorDomain {
        BitvectorDomain::Value(bitvector)
    }
}

impl TryToBitvec for BitvectorDomain {
    /// If the domain represents an absoulute value, return it.
    fn try_to_bitvec(&self) -> Result<Bitvector, Error> {
        match self {
            BitvectorDomain::Value(val) => Ok(val.clone()),
            BitvectorDomain::Top(_) => Err(anyhow!("Value is Top")),
        }
    }
}

impl TryToInterval for BitvectorDomain {
    /// If the domain represents an absolute value, return it as an interval of length one.
    fn try_to_interval(&self) -> Result<Interval, Error> {
        match self {
            BitvectorDomain::Value(val) => Ok(val.clone().into()),
            BitvectorDomain::Top(_) => Err(anyhow!("Value is Top")),
        }
    }
}

impl std::fmt::Display for BitvectorDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Top(bytesize) => write!(formatter, "Top:u{}", bytesize.as_bit_length()),
            Self::Value(bitvector) => write!(
                formatter,
                "0x{:016x}:u{:?}",
                bitvector,
                bitvector.width().to_usize()
            ),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bitvec;

    fn bv(value: i64) -> BitvectorDomain {
        bitvec!(format!("{}:8", value)).into()
    }

    #[test]
    fn bitvector_domain_as_value_domain() {
        use BinOpType::*;
        use CastOpType::*;
        use UnOpType::*;
        let eight = bv(8);
        let sixteen = bv(16);

        assert_eq!(sixteen.bin_op(IntAdd, &eight), bv(24));
        assert_eq!(sixteen.bin_op(IntSub, &eight), bv(8));
        assert_eq!(sixteen.bin_op(IntMult, &eight), bv(16 * 8));
        assert_eq!(sixteen.bin_op(IntDiv, &eight), bv(2));
        assert_eq!(sixteen.bin_op(IntSDiv, &eight), bv(2));
        assert_eq!(sixteen.bin_op(IntRem, &eight), bv(0));
        assert_eq!(sixteen.bin_op(IntSRem, &eight), bv(0));
        assert_eq!(sixteen.bin_op(IntLeft, &bv(2)), bv(64));
        assert_eq!(sixteen.bin_op(IntRight, &bv(2)), bv(4));
        assert_eq!(sixteen.bin_op(IntSRight, &bv(2)), bv(4));
        assert_eq!(sixteen.bin_op(IntAnd, &eight), bv(0));
        assert_eq!(sixteen.bin_op(IntOr, &eight), bv(24));
        assert_eq!(sixteen.bin_op(IntXOr, &eight), bv(24));

        assert_eq!(
            sixteen.bin_op(IntEqual, &bv(16)),
            BitvectorDomain::Value(bitvec!(format!("{}:1", true as u8)))
        );
        assert_eq!(
            sixteen.bin_op(IntNotEqual, &bv(16)),
            BitvectorDomain::Value(bitvec!(format!("{}:1", false as u8)))
        );

        assert_eq!(sixteen.un_op(Int2Comp), bv(-16));
        assert_eq!(bv(0).un_op(IntNegate), bv(-1));

        assert_eq!(
            sixteen.subpiece(ByteSize::new(0), ByteSize::new(4)),
            BitvectorDomain::Value(bitvec!("16:4"))
        );
        assert_eq!(
            sixteen.subpiece(ByteSize::new(4), ByteSize::new(4)),
            BitvectorDomain::Value(bitvec!("0:4"))
        );

        assert_eq!(
            BitvectorDomain::Value(bitvec!("2:4")),
            bv(2 << 32).subpiece(ByteSize::new(4), ByteSize::new(4))
        );

        assert_eq!(
            BitvectorDomain::Value(bitvec!("-1:4"))
                .bin_op(Piece, &BitvectorDomain::Value(bitvec!("-1:4"))),
            bv(-1)
        );

        assert_eq!(
            BitvectorDomain::Value(bitvec!("-1:4")).cast(PopCount, ByteSize::new(8)),
            bv(32)
        )
    }

    #[test]
    fn bitvector_domain_as_abstract_domain() {
        assert_eq!(bv(17).merge(&bv(17)), bv(17));
        assert_eq!(
            bv(17).merge(&bv(16)),
            BitvectorDomain::new_top(ByteSize::new(8))
        );
        assert!(!bv(17).is_top());
        assert!(BitvectorDomain::new_top(ByteSize::new(8)).is_top());
    }

    #[test]
    fn arshift() {
        use BinOpType::IntSRight;
        let positive_x = bv(31);
        let negative_x = bv(-31);
        let shift_3 = BitvectorDomain::Value(bitvec!("3:1"));
        let shift_70 = BitvectorDomain::Value(bitvec!("70:1"));
        assert_eq!(positive_x.bin_op(IntSRight, &shift_3), bv(3));
        assert_eq!(positive_x.bin_op(IntSRight, &shift_70), bv(0));
        assert_eq!(negative_x.bin_op(IntSRight, &shift_3), bv(-4));
        assert_eq!(negative_x.bin_op(IntSRight, &shift_70), bv(-1));
    }

    #[test]
    fn float_nan_bytesize() {
        let top_value = BitvectorDomain::new_top(ByteSize::new(8));
        let result = top_value.un_op(UnOpType::FloatNaN);
        assert!(result.is_top());
        assert_eq!(result.bytesize(), ByteSize::new(1));
    }
}
