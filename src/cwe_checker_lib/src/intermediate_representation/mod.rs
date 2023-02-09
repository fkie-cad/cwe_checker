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

mod bitvector;
pub use bitvector::*;
mod variable;
pub use variable::*;
mod expression;
pub use expression::*;
mod term;
pub use term::*;
mod def;
pub use def::*;
mod jmp;
pub use jmp::*;
mod blk;
pub use blk::*;
mod sub;
pub use sub::*;
mod program;
pub use program::*;
mod project;
pub use project::*;
mod runtime_memory_image;
pub use runtime_memory_image::*;
#[cfg(test)]
#[macro_use]
mod macros;
#[cfg(test)]
pub use macros::*;

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

impl From<ByteSize> for apint::BitWidth {
    fn from(bytesize: ByteSize) -> apint::BitWidth {
        apint::BitWidth::from((u64::from(bytesize) * 8) as usize)
    }
}

impl From<apint::BitWidth> for ByteSize {
    /// Convert to `ByteSize`, while always rounding up to the nearest full byte.
    fn from(bitwidth: apint::BitWidth) -> ByteSize {
        ByteSize::new((bitwidth.to_usize() + 7) as u64 / 8)
    }
}

impl ByteSize {
    /// Create a new `ByteSize` object
    pub fn new(value: u64) -> ByteSize {
        ByteSize(value)
    }

    /// Convert to the equivalent size in bits (by multiplying with 8).
    pub fn as_bit_length(self) -> usize {
        (u64::from(self) * 8) as usize
    }
}

/// Properties of C/C++ data types such as size.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DatatypeProperties {
    /// Holds the size of the char type
    pub char_size: ByteSize,
    /// Holds the size of the double type
    pub double_size: ByteSize,
    /// Holds the size of the float type
    pub float_size: ByteSize,
    /// Holds the size of the integer type
    pub integer_size: ByteSize,
    /// Holds the size of the long double type
    pub long_double_size: ByteSize,
    /// Holds the size of the long long type
    pub long_long_size: ByteSize,
    /// Holds the size of the long type
    pub long_size: ByteSize,
    /// Holds the size of the pointer type
    pub pointer_size: ByteSize,
    /// Holds the size of the short type
    pub short_size: ByteSize,
}

impl DatatypeProperties {
    /// Matches a given data type with its size from the properties struct.
    pub fn get_size_from_data_type(&self, data_type: Datatype) -> ByteSize {
        match data_type {
            Datatype::Char => self.char_size,
            Datatype::Double => self.double_size,
            Datatype::Float => self.float_size,
            Datatype::Integer => self.integer_size,
            Datatype::LongDouble => self.long_double_size,
            Datatype::LongLong => self.long_long_size,
            Datatype::Long => self.long_size,
            Datatype::Pointer => self.pointer_size,
            Datatype::Short => self.short_size,
        }
    }
}

/// C/C++ data types.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Datatype {
    /// C char data type
    Char,
    /// C double data type
    Double,
    /// C float data type
    Float,
    /// C integer data type
    Integer,
    /// C long double data type
    LongDouble,
    /// C long long data type
    LongLong,
    /// C long data type
    Long,
    /// C pointer data type
    Pointer,
    /// C short data type
    Short,
}

impl From<String> for Datatype {
    /// The purpose of this conversion is to locate parameters to variadic functions.
    /// Therefore, char types have to be mapped to the integer size since they undergo the default
    /// argument promotion. (e.g. 1 byte char -> 4 byte integer)
    /// The same holds for all float types that are promoted to doubles. (e.g. 8 byte float -> 16 byte double)
    fn from(specifier: String) -> Self {
        match specifier.as_str() {
            "c" | "C" => Datatype::Char,
            "d" | "i" | "u" | "o" | "p" | "x" | "X" | "hi" | "hd" | "hu" => Datatype::Integer,
            "s" | "S" | "n" => Datatype::Pointer,
            "lf" | "lg" | "le" | "la" | "lF" | "lG" | "lE" | "lA" | "f" | "F" | "e" | "E" | "a"
            | "A" | "g" | "G" => Datatype::Double,
            "li" | "ld" | "lu" => Datatype::Long,
            "lli" | "lld" | "llu" => Datatype::LongLong,
            "Lf" | "Lg" | "Le" | "La" | "LF" | "LG" | "LE" | "LA" => Datatype::LongDouble,
            _ => panic!("Invalid data type specifier from format string."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apint::BitWidth;

    #[test]
    fn check_bit_to_byte_conversion() {
        let bits: BitWidth = BitWidth::new(8).unwrap();
        let bytes: ByteSize = bits.into();
        assert_eq!(u64::from(bytes), 1);
        let bits: BitWidth = bytes.into();
        assert_eq!(bits.to_usize(), 8);

        assert_eq!(ByteSize::new(2).as_bit_length(), 16);
    }
}
