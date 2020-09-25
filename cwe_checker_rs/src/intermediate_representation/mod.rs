use crate::prelude::*;
use derive_more::*;
use std::convert::TryFrom;

mod variable;
pub use variable::*;
mod expression;
pub use expression::*;
mod term;
pub use term::*;

// TODO: move ByteSize and BitSize into their own module
#[derive(
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Display,
    Binary,
    Octal,
    LowerHex,
    UpperHex,
    From,
    Into,
    Not,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shr,
    Shl,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    RemAssign,
    ShrAssign,
    ShlAssign,
    Sum,
)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl From<ByteSize> for BitSize {
    fn from(bytesize: ByteSize) -> BitSize {
        u16::try_from(u64::from(bytesize) * 8).unwrap()
    }
}

impl From<ByteSize> for apint::BitWidth {
    fn from(bytesize: ByteSize) -> apint::BitWidth {
        apint::BitWidth::from((u64::from(bytesize) * 8) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_bit_to_byte_conversion() {
        let bits: BitSize = 8;
        let bytes: ByteSize = bits.into();
        assert_eq!(u64::from(bytes), 1);
        let bits: BitSize = bytes.into();
        assert_eq!(bits, 8);
    }
}
