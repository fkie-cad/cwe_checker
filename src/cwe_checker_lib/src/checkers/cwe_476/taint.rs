use crate::abstract_domain::{AbstractDomain, HasTop, RegisterDomain, SizedDomain};
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::fmt::Display;

/// An abstract domain representing a value that is either tainted or not.
///
/// Note that the [merge](Taint::merge)-function does not respect the partial order
/// that is implied by the naming scheme of the variants!
/// In fact the whole analysis does not enforce any partial order for this domain.
/// This means that in theory the fixpoint computation may not actually converge to a fixpoint,
/// but in practice the analysis can make more precise decisions
/// whether a value should be tainted or not.
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
            Self::Tainted(size) => write!(f, "Tainted:{size}"),
            Self::Top(size) => write!(f, "Top:{size}"),
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

impl SizedDomain for Taint {
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

impl RegisterDomain for Taint {
    /// The result of a binary operation is tainted if at least one input value was tainted.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Tainted(_), _) | (_, Self::Tainted(_)) => {
                Self::Tainted(self.bin_op_bytesize(op, rhs))
            }
            _ => Self::Top(self.bin_op_bytesize(op, rhs)),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_domain() {
        let taint = Taint::Tainted(ByteSize::new(4));
        let top = Taint::Top(ByteSize::new(4));
        assert_eq!(taint.merge(&top), taint);
        assert_eq!(top.merge(&top), top);
        assert_eq!(taint.is_top(), false);
    }

    #[test]
    fn register_domain() {
        use crate::intermediate_representation::*;
        let taint = Taint::Tainted(ByteSize::new(4));
        let top = Taint::Top(ByteSize::new(4));
        assert_eq!(taint.bin_op(BinOpType::IntAdd, &top), taint);
        assert_eq!(top.bin_op(BinOpType::IntMult, &top), top);
        assert_eq!(taint.un_op(UnOpType::FloatFloor), taint);
        assert_eq!(taint.subpiece(ByteSize::new(0), ByteSize::new(4)), taint);
        assert_eq!(top.cast(CastOpType::IntZExt, ByteSize::new(4)), top);
    }
}
