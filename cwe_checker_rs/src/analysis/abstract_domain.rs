use crate::bil::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};

/// The main trait describing an abstract domain.
///
/// Each abstract domain is partially ordered and has a maximal element (which can be generated by `top()`).
/// Abstract domains of the same type can be merged.
///
/// TODO: Decide if and how to represent intersects and bottom values!
pub trait AbstractDomain: Sized + Eq + Clone {
    /// The maximal value of a domain.
    /// Usually it indicates a value for which nothing is known.
    fn top(&self) -> Self;

    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            self.top()
        }
    }

    /// Returns whether the element represents the top element or not.
    fn is_top(&self) -> bool {
        *self == self.top()
    }
}

/// A trait for abstract domains that represent values that can be loaded into register or written onto the stack.
/// Every value has a determined and immutable length (in bits).
pub trait ValueDomain: AbstractDomain {
    /// Returns the size of the value in bits
    fn bitsize(&self) -> BitSize;

    /// Return a new top element with the given bitsize
    fn new_top(bitsize: BitSize) -> Self;

    /// Compute the (abstract) result of a binary operation
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self;

    /// Compute the (abstract) result of a unary operation
    fn un_op(&self, op: UnOpType) -> Self;

    /// extract a sub-bitvector
    fn extract(&self, low_bit: BitSize, high_bit: BitSize) -> Self {
        Self::new_top(high_bit - low_bit) // TODO: This needs a unit test whether the result has the correct bitwidth!
    }

    /// Extend a bitvector using the given cast type
    fn cast(&self, kind: CastType, width: BitSize) -> Self;

    /// Concatenate two bitvectors
    fn concat(&self, other: &Self) -> Self {
        Self::new_top(self.bitsize() + other.bitsize())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum BitvectorDomain {
    Top(BitSize),
    Value(Bitvector),
}

impl ValueDomain for BitvectorDomain {
    fn bitsize(&self) -> BitSize {
        use BitvectorDomain::*;
        match self {
            Top(bitsize) => *bitsize,
            Value(bitvec) => bitvec.width().to_usize() as u16,
        }
    }

    fn new_top(bitsize: BitSize) -> BitvectorDomain {
        BitvectorDomain::Top(bitsize)
    }

    /// Evaluate the given binary operation.
    /// Note that this function assumes that both values have the same bitsize.
    /// If not, this function should panic.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        assert_eq!(self.bitsize(), rhs.bitsize());
        match (self, rhs) {
            (BitvectorDomain::Value(lhs_bitvec), BitvectorDomain::Value(rhs_bitvec)) => match op {
                PLUS => BitvectorDomain::Value(lhs_bitvec + rhs_bitvec),
                MINUS => BitvectorDomain::Value(lhs_bitvec - rhs_bitvec),
                TIMES => BitvectorDomain::Value(lhs_bitvec * rhs_bitvec),
                DIVIDE => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_udiv(rhs_bitvec).unwrap(),
                ),
                SDIVIDE => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_sdiv(rhs_bitvec).unwrap(),
                ),
                MOD => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_urem(rhs_bitvec).unwrap(),
                ),
                SMOD => BitvectorDomain::Value(
                    lhs_bitvec.clone().into_checked_srem(rhs_bitvec).unwrap(),
                ),
                LSHIFT => BitvectorDomain::Value(
                    lhs_bitvec
                        .clone()
                        .into_checked_shl(rhs_bitvec.try_to_u64().unwrap() as usize)
                        .unwrap(),
                ),
                RSHIFT => BitvectorDomain::Value(
                    lhs_bitvec
                        .clone()
                        .into_checked_lshr(rhs_bitvec.try_to_u64().unwrap() as usize)
                        .unwrap(),
                ),
                ARSHIFT => BitvectorDomain::Value(
                    lhs_bitvec
                        .clone()
                        .into_checked_ashr(rhs_bitvec.try_to_u64().unwrap() as usize)
                        .unwrap(),
                ),
                AND => BitvectorDomain::Value(lhs_bitvec & rhs_bitvec),
                OR => BitvectorDomain::Value(lhs_bitvec | rhs_bitvec),
                XOR => BitvectorDomain::Value(lhs_bitvec ^ rhs_bitvec),
                EQ => {
                    assert_eq!(lhs_bitvec.width(), rhs_bitvec.width());
                    BitvectorDomain::Value(Bitvector::from(lhs_bitvec == rhs_bitvec))
                }
                NEQ => {
                    assert_eq!(lhs_bitvec.width(), rhs_bitvec.width());
                    BitvectorDomain::Value(Bitvector::from(lhs_bitvec != rhs_bitvec))
                }
                LT => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_ult(rhs_bitvec).unwrap(),
                )),
                LE => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_ule(rhs_bitvec).unwrap(),
                )),
                SLT => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_slt(rhs_bitvec).unwrap(),
                )),
                SLE => BitvectorDomain::Value(Bitvector::from(
                    lhs_bitvec.checked_sle(rhs_bitvec).unwrap(),
                )),
            },
            _ => match op {
                PLUS | MINUS | TIMES | DIVIDE | SDIVIDE | MOD | SMOD | LSHIFT | RSHIFT
                | ARSHIFT | AND | OR | XOR => BitvectorDomain::new_top(self.bitsize()),
                EQ | NEQ | LT | LE | SLT | SLE => BitvectorDomain::new_top(1),
            },
        }
    }

    /// Evaluate the given unary operation.
    fn un_op(&self, op: UnOpType) -> Self {
        use UnOpType::*;
        if let BitvectorDomain::Value(bitvec) = self {
            match op {
                NEG => BitvectorDomain::Value(-bitvec),
                NOT => BitvectorDomain::Value(bitvec.clone().into_bitnot()),
            }
        } else {
            BitvectorDomain::new_top(self.bitsize())
        }
    }

    /// Extract a sub-bitvector out of a bitvector
    fn extract(&self, low_bit: BitSize, high_bit: BitSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            // TODO: Check whether this is correct on a real world example and then write a unit test for it
            BitvectorDomain::Value(
                bitvec
                    .clone()
                    .into_checked_lshr(low_bit as usize)
                    .unwrap()
                    .into_truncate((high_bit - low_bit + 1) as usize)
                    .unwrap(),
            )
        } else {
            BitvectorDomain::new_top(self.bitsize())
        }
    }

    fn cast(&self, kind: CastType, width: BitSize) -> Self {
        if let BitvectorDomain::Value(bitvec) = self {
            use CastType::*;
            match kind {
                UNSIGNED => {
                    BitvectorDomain::Value(bitvec.clone().into_zero_extend(width as usize).unwrap())
                }
                SIGNED => {
                    BitvectorDomain::Value(bitvec.clone().into_sign_extend(width as usize).unwrap())
                }
                HIGH => BitvectorDomain::Value(
                    bitvec
                        .clone()
                        .into_checked_lshr((self.bitsize() - width) as usize)
                        .unwrap()
                        .into_truncate(width as usize)
                        .unwrap(),
                ),
                LOW => {
                    BitvectorDomain::Value(bitvec.clone().into_truncate(width as usize).unwrap())
                }
            }
        } else {
            BitvectorDomain::new_top(width)
        }
    }

    fn concat(&self, other: &Self) -> Self {
        match (self, other) {
            (BitvectorDomain::Value(left_bitvec), BitvectorDomain::Value(right_bitvec)) => {
                let new_bitwidth = (self.bitsize() + other.bitsize()) as usize;
                let upper_bits = left_bitvec
                    .clone()
                    .into_zero_extend(new_bitwidth)
                    .unwrap()
                    .into_checked_shl(other.bitsize() as usize)
                    .unwrap();
                let lower_bits = right_bitvec.clone().into_zero_extend(new_bitwidth).unwrap();
                BitvectorDomain::Value(upper_bits | &lower_bits)
            }
            _ => BitvectorDomain::new_top(self.bitsize() + other.bitsize()),
        }
    }
}

impl AbstractDomain for BitvectorDomain {
    fn top(&self) -> BitvectorDomain {
        BitvectorDomain::Top(self.bitsize())
    }
}

impl std::ops::Add for BitvectorDomain {
    type Output = BitvectorDomain;

    fn add(self, rhs: Self) -> Self {
        assert_eq!(self.bitsize(), rhs.bitsize());
        self.bin_op(crate::bil::BinOpType::PLUS, &rhs)
    }
}

impl std::ops::Sub for BitvectorDomain {
    type Output = BitvectorDomain;

    fn sub(self, rhs: Self) -> Self {
        assert_eq!(self.bitsize(), rhs.bitsize());
        self.bin_op(crate::bil::BinOpType::MINUS, &rhs)
    }
}

impl std::ops::Neg for BitvectorDomain {
    type Output = BitvectorDomain;

    fn neg(self) -> Self {
        self.un_op(crate::bil::UnOpType::NEG)
    }
}

impl std::convert::From<Bitvector> for BitvectorDomain {
    fn from(bitvector: Bitvector) -> BitvectorDomain {
        BitvectorDomain::Value(bitvector)
    }
}

impl std::fmt::Display for BitvectorDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Top(bitsize) => write!(formatter, "Top:i{}", bitsize),
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
        use crate::bil::BinOpType::*;
        use crate::bil::CastType::*;
        use crate::bil::UnOpType::*;
        let eight = bv(8);
        let sixteen = bv(16);

        assert_eq!(sixteen.bin_op(PLUS, &eight), bv(24));
        assert_eq!(sixteen.bin_op(MINUS, &eight), bv(8));
        assert_eq!(sixteen.bin_op(TIMES, &eight), bv(16 * 8));
        assert_eq!(sixteen.bin_op(DIVIDE, &eight), bv(2));
        assert_eq!(sixteen.bin_op(SDIVIDE, &eight), bv(2));
        assert_eq!(sixteen.bin_op(MOD, &eight), bv(0));
        assert_eq!(sixteen.bin_op(SMOD, &eight), bv(0));
        assert_eq!(sixteen.bin_op(LSHIFT, &bv(2)), bv(64));
        assert_eq!(sixteen.bin_op(RSHIFT, &bv(2)), bv(4));
        assert_eq!(sixteen.bin_op(ARSHIFT, &bv(2)), bv(4));
        assert_eq!(sixteen.bin_op(AND, &eight), bv(0));
        assert_eq!(sixteen.bin_op(OR, &eight), bv(24));
        assert_eq!(sixteen.bin_op(XOR, &eight), bv(24));

        assert_eq!(
            sixteen.bin_op(EQ, &bv(16)),
            BitvectorDomain::Value(Bitvector::from_bit(true))
        );
        assert_eq!(
            sixteen.bin_op(NEQ, &bv(16)),
            BitvectorDomain::Value(Bitvector::from_bit(false))
        );

        assert_eq!(sixteen.un_op(NEG), bv(-16));
        assert_eq!(bv(0).un_op(NOT), bv(-1));

        assert_eq!(
            sixteen.extract(0, 31),
            BitvectorDomain::Value(Bitvector::from_i32(16))
        );
        assert_eq!(
            sixteen.extract(32, 63),
            BitvectorDomain::Value(Bitvector::from_i32(0))
        );

        assert_eq!(
            BitvectorDomain::Value(Bitvector::from_i32(2)),
            BitvectorDomain::Value(Bitvector::from_i64(2 << 32)).cast(HIGH, 32)
        );

        assert_eq!(
            BitvectorDomain::Value(Bitvector::from_i32(-1))
                .concat(&BitvectorDomain::Value(Bitvector::from_i32(-1))),
            bv(-1)
        );
    }

    #[test]
    fn bitvector_domain_as_abstract_domain() {
        assert_eq!(bv(17).merge(&bv(17)), bv(17));
        assert_eq!(bv(17).merge(&bv(16)), BitvectorDomain::new_top(64));
        assert!(!bv(17).is_top());
        assert!(BitvectorDomain::new_top(64).is_top());
    }
}
