use super::{AbstractDomain, HasByteSize, HasTop, RegisterDomain};
use crate::bil::BitSize;
use crate::intermediate_representation::*;
use crate::prelude::*;

/// The `BitvectorDomain` is a simple abstract domain describing a bitvector of known length.
///
/// As values it can only assume a known bitvector or *Top(bytesize)*.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum BitvectorDomain {
    Top(ByteSize),
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

impl HasByteSize for BitvectorDomain {
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
            (BitvectorDomain::Value(lhs_bitvec), BitvectorDomain::Value(rhs_bitvec)) => match op {
                Piece => {
                    let new_bitwidth = BitSize::from(self.bytesize() + rhs.bytesize());
                    let upper_bits = lhs_bitvec
                        .clone()
                        .into_zero_extend(new_bitwidth as usize)
                        .unwrap()
                        .into_checked_shl(BitSize::from(rhs.bytesize()) as usize)
                        .unwrap();
                    let lower_bits = rhs_bitvec
                        .clone()
                        .into_zero_extend(new_bitwidth as usize)
                        .unwrap();
                    BitvectorDomain::Value(upper_bits | &lower_bits)
                }
                IntAdd => BitvectorDomain::Value(lhs_bitvec + rhs_bitvec),
                IntSub => BitvectorDomain::Value(lhs_bitvec - rhs_bitvec),
                IntCarry => {
                    let result = lhs_bitvec + rhs_bitvec;
                    if result.checked_ult(lhs_bitvec).unwrap()
                        || result.checked_ult(rhs_bitvec).unwrap()
                    {
                        Bitvector::from_u8(1).into()
                    } else {
                        Bitvector::from_u8(0).into()
                    }
                }
                IntSCarry => {
                    let result = apint::Int::from(lhs_bitvec + rhs_bitvec);
                    let lhs_bitvec = apint::Int::from(lhs_bitvec.clone());
                    let rhs_bitvec = apint::Int::from(rhs_bitvec.clone());
                    if (result.is_negative()
                        && lhs_bitvec.is_positive()
                        && rhs_bitvec.is_positive())
                        || (!result.is_negative()
                            && lhs_bitvec.is_negative()
                            && rhs_bitvec.is_negative())
                    {
                        Bitvector::from_u8(1).into()
                    } else {
                        Bitvector::from_u8(0).into()
                    }
                }
                IntSBorrow => {
                    let result = apint::Int::from(lhs_bitvec - rhs_bitvec);
                    let lhs_bitvec = apint::Int::from(lhs_bitvec.clone());
                    let rhs_bitvec = apint::Int::from(rhs_bitvec.clone());
                    if (result.is_negative()
                        && !lhs_bitvec.is_positive()
                        && rhs_bitvec.is_negative())
                        || (result.is_positive()
                            && lhs_bitvec.is_negative()
                            && rhs_bitvec.is_positive())
                    {
                        Bitvector::from_u8(1).into()
                    } else {
                        Bitvector::from_u8(0).into()
                    }
                }
                IntMult => BitvectorDomain::Value(lhs_bitvec * rhs_bitvec),
                IntDiv => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_udiv(rhs_bitvec).unwrap(),
                ),
                IntSDiv => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_sdiv(rhs_bitvec).unwrap(),
                ),
                IntRem => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_urem(rhs_bitvec).unwrap(),
                ),
                IntSRem => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_srem(rhs_bitvec).unwrap(),
                ),
                IntLeft => {
                    let shift_amount = rhs_bitvec.try_to_u64().unwrap() as usize;
                    if shift_amount < lhs_bitvec.width().to_usize() {
                        BitvectorDomain::Value(
                            lhs_bitvec.clone().into_checked_shl(shift_amount).unwrap(),
                        )
                    } else {
                        BitvectorDomain::Value(Bitvector::zero(lhs_bitvec.width()))
                    }
                }
                IntRight => {
                    let shift_amount = rhs_bitvec.try_to_u64().unwrap() as usize;
                    if shift_amount < lhs_bitvec.width().to_usize() {
                        BitvectorDomain::Value(
                            lhs_bitvec.clone().into_checked_lshr(shift_amount).unwrap(),
                        )
                    } else {
                        BitvectorDomain::Value(Bitvector::zero(lhs_bitvec.width()))
                    }
                }
                IntSRight => {
                    let shift_amount = rhs_bitvec.try_to_u64().unwrap() as usize;
                    if shift_amount < lhs_bitvec.width().to_usize() {
                        BitvectorDomain::Value(
                            lhs_bitvec.clone().into_checked_ashr(shift_amount).unwrap(),
                        )
                    } else {
                        let signed_bitvec = apint::Int::from(lhs_bitvec.clone());
                        if signed_bitvec.is_negative() {
                            let minus_one = Bitvector::zero(lhs_bitvec.width())
                                - &Bitvector::one(lhs_bitvec.width());
                            BitvectorDomain::Value(minus_one)
                        } else {
                            BitvectorDomain::Value(Bitvector::zero(lhs_bitvec.width()))
                        }
                    }
                }
                IntAnd | BoolAnd => BitvectorDomain::Value(lhs_bitvec & rhs_bitvec),
                IntOr | BoolOr => BitvectorDomain::Value(lhs_bitvec | rhs_bitvec),
                IntXOr | BoolXOr => BitvectorDomain::Value(lhs_bitvec ^ rhs_bitvec),
                IntEqual => {
                    assert_eq!(lhs_bitvec.width(), rhs_bitvec.width());
                    BitvectorDomain::Value(Bitvector::from((lhs_bitvec == rhs_bitvec) as u8))
                }
                IntNotEqual => {
                    assert_eq!(lhs_bitvec.width(), rhs_bitvec.width());
                    BitvectorDomain::Value(Bitvector::from((lhs_bitvec != rhs_bitvec) as u8))
                }
                IntLess => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_ult(rhs_bitvec).unwrap() as u8,
                )),
                IntLessEqual => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_ule(rhs_bitvec).unwrap() as u8,
                )),
                IntSLess => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_slt(rhs_bitvec).unwrap() as u8,
                )),
                IntSLessEqual => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_sle(rhs_bitvec).unwrap() as u8,
                )),
                FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual => {
                    // TODO: Implement floating point comparison operators!
                    BitvectorDomain::new_top(ByteSize::new(1))
                }
                FloatAdd | FloatSub | FloatMult | FloatDiv => {
                    // TODO: Implement floating point arithmetic operators!
                    BitvectorDomain::new_top(self.bytesize())
                }
            },
            _ => BitvectorDomain::new_top(self.bin_op_bytesize(op, rhs)),
        }
    }

    /// Evaluate the given unary operation.
    fn un_op(&self, op: UnOpType) -> Self {
        use UnOpType::*;
        if let BitvectorDomain::Value(bitvec) = self {
            match op {
                Int2Comp => BitvectorDomain::Value(-bitvec),
                IntNegate => BitvectorDomain::Value(bitvec.clone().into_bitnot()),
                BoolNegate => {
                    if bitvec.is_zero() {
                        BitvectorDomain::Value(Bitvector::from_u8(1))
                    } else {
                        BitvectorDomain::Value(Bitvector::from_u8(0))
                    }
                }
                FloatNegate | FloatAbs | FloatSqrt | FloatCeil | FloatFloor | FloatRound
                | FloatNaN => BitvectorDomain::new_top(self.bytesize()),
            }
        } else {
            match op {
                BoolNegate => BitvectorDomain::new_top(ByteSize::new(1)),
                _ => BitvectorDomain::new_top(self.bytesize()),
            }
        }
    }

    /// Extract a sub-bitvector out of a bitvector
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            BitvectorDomain::Value(
                bitvec
                    .clone()
                    .into_checked_lshr(BitSize::from(low_byte) as usize)
                    .unwrap()
                    .into_truncate(BitSize::from(size) as usize)
                    .unwrap(),
            )
        } else {
            BitvectorDomain::new_top(size)
        }
    }

    /// Perform a size-changing cast on a bitvector.
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            use CastOpType::*;
            match kind {
                IntZExt => BitvectorDomain::Value(
                    bitvec
                        .clone()
                        .into_zero_extend(apint::BitWidth::from(width))
                        .unwrap(),
                ),
                IntSExt => BitvectorDomain::Value(
                    bitvec
                        .clone()
                        .into_sign_extend(apint::BitWidth::from(width))
                        .unwrap(),
                ),
                PopCount => BitvectorDomain::Value(
                    Bitvector::from_u64(bitvec.count_ones() as u64)
                        .into_truncate(apint::BitWidth::from(width))
                        .unwrap(),
                ),
                Int2Float | Float2Float | Trunc => BitvectorDomain::new_top(width),
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

impl std::convert::TryFrom<&BitvectorDomain> for Bitvector {
    type Error = ();
    fn try_from(bitvec_domain: &BitvectorDomain) -> Result<Bitvector, ()> {
        match bitvec_domain {
            BitvectorDomain::Value(bitvec) => Ok(bitvec.clone()),
            BitvectorDomain::Top(_) => Err(()),
        }
    }
}

impl std::fmt::Display for BitvectorDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Top(bytesize) => write!(formatter, "Top:i{}", BitSize::from(*bytesize)),
            Self::Value(bitvector) => write!(
                formatter,
                "0x{:016x}:i{:?}",
                bitvector,
                bitvector.width().to_usize()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
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
            BitvectorDomain::Value(Bitvector::from_u8(true as u8))
        );
        assert_eq!(
            sixteen.bin_op(IntNotEqual, &bv(16)),
            BitvectorDomain::Value(Bitvector::from_u8(false as u8))
        );

        assert_eq!(sixteen.un_op(Int2Comp), bv(-16));
        assert_eq!(bv(0).un_op(IntNegate), bv(-1));

        assert_eq!(
            sixteen.subpiece(ByteSize::new(0), ByteSize::new(4)),
            BitvectorDomain::Value(Bitvector::from_i32(16))
        );
        assert_eq!(
            sixteen.subpiece(ByteSize::new(4), ByteSize::new(4)),
            BitvectorDomain::Value(Bitvector::from_i32(0))
        );

        assert_eq!(
            BitvectorDomain::Value(Bitvector::from_i32(2)),
            BitvectorDomain::Value(Bitvector::from_i64(2 << 32))
                .subpiece(ByteSize::new(4), ByteSize::new(4))
        );

        assert_eq!(
            BitvectorDomain::Value(Bitvector::from_i32(-1))
                .bin_op(Piece, &BitvectorDomain::Value(Bitvector::from_i32(-1))),
            bv(-1)
        );

        assert_eq!(
            BitvectorDomain::Value(Bitvector::from_i32(-1)).cast(PopCount, ByteSize::new(8)),
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
        let positive_x = BitvectorDomain::Value(Bitvector::from_i64(31));
        let negative_x = BitvectorDomain::Value(Bitvector::from_i64(-31));
        let shift_3 = BitvectorDomain::Value(Bitvector::from_u8(3));
        let shift_70 = BitvectorDomain::Value(Bitvector::from_u8(70));
        assert_eq!(
            positive_x.bin_op(IntSRight, &shift_3),
            BitvectorDomain::Value(Bitvector::from_i64(3))
        );
        assert_eq!(
            positive_x.bin_op(IntSRight, &shift_70),
            BitvectorDomain::Value(Bitvector::from_i64(0))
        );
        assert_eq!(
            negative_x.bin_op(IntSRight, &shift_3),
            BitvectorDomain::Value(Bitvector::from_i64(-4))
        );
        assert_eq!(
            negative_x.bin_op(IntSRight, &shift_70),
            BitvectorDomain::Value(Bitvector::from_i64(-1))
        );
    }
}
