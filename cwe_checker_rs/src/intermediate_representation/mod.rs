//! This module defines the intermediate representation used to represent a binary
//! and all its contained executable code.
//!
//! The main data structure is the `Project` struct,
//! which contains all information recovered about a binary during the disassembly step.
//! To learn how individual instructions are encoded,
//! you should first take a look at the `Expression` type and then at the `Def` and `Jmp` data types,
//! which form the basis of the basic block `Blk` struct.

use crate::prelude::*;
use derive_more::*;
use std::convert::TryFrom;

mod variable;
pub use variable::*;
mod expression;
pub use expression::*;
mod term;
pub use term::*;

/// An unsigned number of bytes.
/// 
/// Used to represent sizes of values in registers or in memory.
/// Can also be used for other byte-valued numbers, like offsets,
/// as long as the number is guaranteed to be non-negative.
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

impl ByteSize {
    pub fn new(value: u64) -> ByteSize {
        ByteSize(value)
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
