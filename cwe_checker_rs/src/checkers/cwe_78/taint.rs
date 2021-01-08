use std::fmt::Display;

use crate::{abstract_domain::{AbstractDomain, HasByteSize, HasTop, RegisterDomain}, intermediate_representation::BinOpType, intermediate_representation::{ByteSize, CastOpType, UnOpType}};
use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Taint {
    /// A tainted value of a particular bytesize.
    Tainted(ByteSize),
    /// An untainted value of a particular bytesize
    Top(ByteSize),
}

impl Display for Taint {
    /// Print the value of a `Taint` object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tainted(size) => write!(f, "Tainted:{}", size),
            Self::Top(size) => write!(f, "Top:{}", size),
        }
    }
}

impl AbstractDomain for Taint {
    /// The result of merging two `Taint` values is tainted if at least one input was tainted.
    fn merge(&self, other: &Self) -> Self {
        use Taint::*;
        match (self, other) {
            (Tainted(size), _) | (_, Tainted(size)) => Tainted(*size),
            _ => Top(self.bytesize()),
        }
    }

    /// Checks whether the value is an untainted `Top`-value.
    fn is_top(&self) -> bool {
        matches!(self, Taint::Top(_))
    }
}

impl HasByteSize for Taint {
    /// The size in bytes of the `Taint` value.
    fn bytesize(&self) -> ByteSize {
        match self {
            Self::Tainted(size) | Self::Top(size) => *size,
        }
    }
}

impl HasTop for Taint {
    /// Get a new `Top`-value with the same bytesize as `self`.
    fn top(&self) -> Self {
        Self::Top(self.bytesize())
    }
}

impl RegisterDomain for Taint {
    /// Get a new `Top`-value with the given bytesize.
    fn new_top(bytesize: ByteSize) -> Self {
        Self::Top(bytesize)
    }

    /// The result of a binary operation is tainted if at least one input value was tainted.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        *self
    }

    /// The result of a unary operation is tainted if the input was tainted.
    fn un_op(&self, _op: UnOpType) -> Self {
        *self
    }

    /// A subpiece of a tainted value is again tainted.
    fn subpiece(&self, _low_byte: ByteSize, size: ByteSize) -> Self {
        if let Self::Tainted(_) = self {
            Self::Tainted(size)
        } else {
            Self::Top(size)
        }
    }

    /// The result of a cast operation is tainted if the input was tainted.
    fn cast(&self, _kind: CastOpType, width: ByteSize) -> Self {
        if let Self::Tainted(_) = self {
            Self::Tainted(width)
        } else {
            Self::Top(width)
        }
    }
}

impl Taint {
    /// Checks whether the given value is in fact tainted.
    pub fn is_tainted(&self) -> bool {
        matches!(self, Taint::Tainted(_))
    }
}