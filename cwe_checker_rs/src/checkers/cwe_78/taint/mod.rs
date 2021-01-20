use std::fmt::Display;

use crate::prelude::*;
use crate::{
    abstract_domain::{AbstractDomain, HasByteSize, HasTop},
    intermediate_representation::ByteSize,
};

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

    /// Get a new `Top`-value with the given bytesize.
    fn new_top(bytesize: ByteSize) -> Self {
        Self::Top(bytesize)
    }
}

impl HasTop for Taint {
    /// Get a new `Top`-value with the same bytesize as `self`.
    fn top(&self) -> Self {
        Self::Top(self.bytesize())
    }
}

impl Taint {
    /// Checks whether the given value is in fact tainted.
    pub fn is_tainted(&self) -> bool {
        matches!(self, Taint::Tainted(_))
    }
}
