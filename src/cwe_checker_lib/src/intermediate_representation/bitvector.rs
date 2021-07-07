use super::*;

/// A bitvector is a fixed-length vector of bits
/// with the semantics of a CPU register,
/// i.e. it supports two's complement modulo arithmetic.
///
/// Bitvector is just an alias for the [`apint::ApInt`] type.
pub type Bitvector = apint::ApInt;

/// A trait to extend the bitvector type with useful helper functions
/// that are not contained in the [`apint`] crate.
pub trait BitvectorExtended: Sized {
    /// Resize `self` to the target byte size by either zero extending or truncating `self`.
    fn into_resize_unsigned(self, size: ByteSize) -> Self;

    /// Resize `self` to the target byte size by either sign extending or truncating `self`.
    fn into_resize_signed(self, size: ByteSize) -> Self;

    /// Perform a cast operation on the bitvector.
    /// Returns an error for non-implemented cast operations (currently all float-related casts).
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Result<Self, Error>;

    /// Extract a subpiece from the given bitvector.
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self;

    /// Perform a unary operation on the given bitvector.
    /// Returns an error for non-implemented operations (currently all float-related operations).
    fn un_op(&self, op: UnOpType) -> Result<Self, Error>;

    /// Perform a binary operation on the given bitvectors.
    /// Returns an error for non-implemented operations (currently all float-related operations).
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Result<Self, Error>;

    /// Returns the result of `self + rhs` if the computation does not result in a signed integer overflow or underflow.
    fn signed_add_overflow_checked(&self, rhs: &Self) -> Option<Self>;

    /// Returns the result of `self - rhs` if the computation does not result in a signed integer overflow or underflow.
    fn signed_sub_overflow_checked(&self, rhs: &Self) -> Option<Self>;

    /// Return the result of multiplying `self` with `rhs`
    /// and a flag that is set to `true` if the multiplication resulted in a signed integer overflow or underflow.
    ///
    /// Returns an error for bitvectors larger than 8 bytes,
    /// since multiplication for them is not yet implemented in the [`apint`] crate.
    fn signed_mult_with_overflow_flag(&self, rhs: &Self) -> Result<(Self, bool), Error>;

    /// Return the size in bytes of the bitvector.
    fn bytesize(&self) -> ByteSize;
}

impl BitvectorExtended for Bitvector {
    /// Perform a cast operation on the bitvector.
    /// Returns an error for non-implemented cast operations (currently all float-related casts).
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Result<Self, Error> {
        match kind {
            CastOpType::IntZExt => Ok(self.clone().into_zero_extend(width).unwrap()),
            CastOpType::IntSExt => Ok(self.clone().into_sign_extend(width).unwrap()),
            CastOpType::Int2Float | CastOpType::Float2Float | CastOpType::Trunc => {
                Err(anyhow!("Float operations not yet implemented"))
            }
            CastOpType::PopCount => Ok(Bitvector::from_u64(self.count_ones() as u64)
                .into_truncate(width)
                .unwrap()),
        }
    }

    /// Extract a subpiece from the given bitvector.
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        self.clone()
            .into_checked_lshr(low_byte.as_bit_length())
            .unwrap()
            .into_truncate(size.as_bit_length())
            .unwrap()
    }

    /// Perform a unary operation on the given bitvector.
    /// Returns an error for non-implemented operations (currently all float-related operations).
    fn un_op(&self, op: UnOpType) -> Result<Self, Error> {
        use UnOpType::*;
        match op {
            Int2Comp => Ok(-self.clone()),
            IntNegate => Ok(self.clone().into_bitnot()),
            BoolNegate => {
                if self.is_zero() {
                    Ok(Bitvector::from_u8(1))
                } else {
                    Ok(Bitvector::from_u8(0))
                }
            }
            FloatNegate | FloatAbs | FloatSqrt | FloatCeil | FloatFloor | FloatRound | FloatNaN => {
                Err(anyhow!("Float operations not yet implemented"))
            }
        }
    }

    /// Perform a binary operation on the given bitvectors.
    /// Returns an error for non-implemented operations (currently all float-related operations).
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Result<Self, Error> {
        use BinOpType::*;
        match op {
            Piece => {
                let new_bitwidth = self.width().to_usize() + rhs.width().to_usize();
                let upper_bits = self
                    .clone()
                    .into_zero_extend(new_bitwidth)
                    .unwrap()
                    .into_checked_shl(rhs.width().to_usize())
                    .unwrap();
                let lower_bits = rhs.clone().into_zero_extend(new_bitwidth).unwrap();
                Ok(upper_bits | &lower_bits)
            }
            IntAdd => Ok(self + rhs),
            IntSub => Ok(self - rhs),
            IntCarry => {
                let result = self + rhs;
                if result.checked_ult(self).unwrap() || result.checked_ult(rhs).unwrap() {
                    Ok(Bitvector::from_u8(1))
                } else {
                    Ok(Bitvector::from_u8(0))
                }
            }
            IntSCarry => {
                let result = apint::Int::from(self + rhs);
                let signed_self = apint::Int::from(self.clone());
                let signed_rhs = apint::Int::from(rhs.clone());
                if (result.is_negative() && signed_self.is_positive() && signed_rhs.is_positive())
                    || (!result.is_negative()
                        && signed_self.is_negative()
                        && signed_rhs.is_negative())
                {
                    Ok(Bitvector::from_u8(1))
                } else {
                    Ok(Bitvector::from_u8(0))
                }
            }
            IntSBorrow => {
                let result = apint::Int::from(self - rhs);
                let signed_self = apint::Int::from(self.clone());
                let signed_rhs = apint::Int::from(rhs.clone());
                if (result.is_negative() && !signed_self.is_positive() && signed_rhs.is_negative())
                    || (result.is_positive()
                        && signed_self.is_negative()
                        && signed_rhs.is_positive())
                {
                    Ok(Bitvector::from_u8(1))
                } else {
                    Ok(Bitvector::from_u8(0))
                }
            }
            IntMult => {
                // FIXME: Multiplication for bitvectors larger than 8 bytes is not yet implemented in the `apint` crate (version 0.2).
                if self.width().to_usize() > 64 {
                    Err(anyhow!("Multiplication and division of integers larger than 8 bytes not yet implemented."))
                } else {
                    Ok(self * rhs)
                }
            }
            IntDiv => {
                // FIXME: Division for bitvectors larger than 8 bytes is not yet implemented in the `apint` crate (version 0.2).
                if self.width().to_usize() > 64 {
                    Err(anyhow!("Multiplication and division of integers larger than 8 bytes not yet implemented."))
                } else {
                    Ok(self.clone().into_checked_udiv(rhs).unwrap())
                }
            }
            IntSDiv => {
                // FIXME: Division for bitvectors larger than 8 bytes is not yet implemented in the `apint` crate (version 0.2).
                if self.width().to_usize() > 64 {
                    Err(anyhow!("Multiplication and division of integers larger than 8 bytes not yet implemented."))
                } else {
                    Ok(self.clone().into_checked_sdiv(rhs).unwrap())
                }
            }
            IntRem => Ok(self.clone().into_checked_urem(rhs).unwrap()),
            IntSRem => Ok(self.clone().into_checked_srem(rhs).unwrap()),
            IntLeft => {
                let shift_amount = rhs.try_to_u64().unwrap() as usize;
                if shift_amount < self.width().to_usize() {
                    Ok(self.clone().into_checked_shl(shift_amount).unwrap())
                } else {
                    Ok(Bitvector::zero(self.width()))
                }
            }
            IntRight => {
                let shift_amount = rhs.try_to_u64().unwrap() as usize;
                if shift_amount < self.width().to_usize() {
                    Ok(self.clone().into_checked_lshr(shift_amount).unwrap())
                } else {
                    Ok(Bitvector::zero(self.width()))
                }
            }
            IntSRight => {
                let shift_amount = rhs.try_to_u64().unwrap() as usize;
                if shift_amount < self.width().to_usize() {
                    Ok(self.clone().into_checked_ashr(shift_amount).unwrap())
                } else {
                    let signed_bitvec = apint::Int::from(self.clone());
                    if signed_bitvec.is_negative() {
                        let minus_one =
                            Bitvector::zero(self.width()) - &Bitvector::one(self.width());
                        Ok(minus_one)
                    } else {
                        Ok(Bitvector::zero(self.width()))
                    }
                }
            }
            IntAnd | BoolAnd => Ok(self & rhs),
            IntOr | BoolOr => Ok(self | rhs),
            IntXOr | BoolXOr => Ok(self ^ rhs),
            IntEqual => {
                assert_eq!(self.width(), rhs.width());
                Ok(Bitvector::from((self == rhs) as u8))
            }
            IntNotEqual => {
                assert_eq!(self.width(), rhs.width());
                Ok(Bitvector::from((self != rhs) as u8))
            }
            IntLess => Ok(Bitvector::from(self.checked_ult(rhs).unwrap() as u8)),
            IntLessEqual => Ok(Bitvector::from(self.checked_ule(rhs).unwrap() as u8)),
            IntSLess => Ok(Bitvector::from(self.checked_slt(rhs).unwrap() as u8)),
            IntSLessEqual => Ok(Bitvector::from(self.checked_sle(rhs).unwrap() as u8)),
            FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual => {
                // TODO: Implement floating point comparison operators!
                Err(anyhow!("Float operations not yet implemented"))
            }
            FloatAdd | FloatSub | FloatMult | FloatDiv => {
                // TODO: Implement floating point arithmetic operators!
                Err(anyhow!("Float operations not yet implemented"))
            }
        }
    }

    /// Returns the result of `self + rhs` if the computation does not result in a signed integer overflow or underflow.
    fn signed_add_overflow_checked(&self, rhs: &Self) -> Option<Self> {
        let result = self.clone().into_checked_add(rhs).unwrap();
        match (rhs.sign_bit().to_bool(), self.checked_sle(&result).unwrap()) {
            (true, true) | (false, false) => None,
            _ => Some(result),
        }
    }

    /// Returns the result of `self - rhs` if the computation does not result in a signed integer overflow or underflow.
    fn signed_sub_overflow_checked(&self, rhs: &Self) -> Option<Self> {
        let result = self.clone().into_checked_sub(rhs).unwrap();
        match (rhs.sign_bit().to_bool(), self.checked_sge(&result).unwrap()) {
            (true, true) | (false, false) => None,
            _ => Some(result),
        }
    }

    /// Return the result of multiplying `self` with `rhs`
    /// and a flag that is set to `true` if the multiplication resulted in a signed integer overflow or underflow.
    ///
    /// Returns an error for bitvectors larger than 8 bytes,
    /// since multiplication for them is not yet implemented in the [`apint`] crate.
    fn signed_mult_with_overflow_flag(&self, rhs: &Self) -> Result<(Self, bool), Error> {
        if self.is_zero() {
            Ok((Bitvector::zero(self.width()), false))
        } else if self.width().to_usize() > 64 {
            // FIXME: Multiplication for bitvectors larger than 8 bytes is not yet implemented in the `apint` crate (version 0.2).
            Err(anyhow!(
                "Multiplication and division of integers larger than 8 bytes not yet implemented."
            ))
        } else {
            let result = self.clone().into_checked_mul(rhs).unwrap();
            if result.clone().into_checked_sdiv(self).unwrap() != *rhs {
                Ok((result, true))
            } else {
                Ok((result, false))
            }
        }
    }

    /// Return the size in bytes of the bitvector.
    fn bytesize(&self) -> ByteSize {
        self.width().into()
    }

    /// Resize `self` to the target byte size by either zero extending or truncating `self`.
    fn into_resize_unsigned(self, size: ByteSize) -> Self {
        if self.width() < size.into() {
            self.into_zero_extend(size).unwrap()
        } else {
            self.into_truncate(size).unwrap()
        }
    }

    /// Resize `self` to the target byte size by either sign extending or truncating `self`.
    fn into_resize_signed(self, size: ByteSize) -> Self {
        if self.width() < size.into() {
            self.into_sign_extend(size).unwrap()
        } else {
            self.into_truncate(size).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_checked_add_and_sub() {
        let max = Bitvector::signed_max_value(ByteSize::new(8).into());
        let min = Bitvector::signed_min_value(ByteSize::new(8).into());

        assert_eq!(min.signed_add_overflow_checked(&min), None);
        assert_eq!(
            min.signed_add_overflow_checked(&max),
            Some(-Bitvector::one(ByteSize::new(8).into()))
        );
        assert_eq!(
            max.signed_add_overflow_checked(&min),
            Some(-Bitvector::one(ByteSize::new(8).into()))
        );
        assert_eq!(max.signed_add_overflow_checked(&max), None);

        assert_eq!(
            min.signed_sub_overflow_checked(&min),
            Some(Bitvector::zero(ByteSize::new(8).into()))
        );
        assert_eq!(min.signed_sub_overflow_checked(&max), None);
        assert_eq!(max.signed_sub_overflow_checked(&min), None);
        assert_eq!(
            max.signed_sub_overflow_checked(&max),
            Some(Bitvector::zero(ByteSize::new(8).into()))
        );
    }
}
