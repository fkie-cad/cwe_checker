use crate::bil::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};

mod bitvector;
pub use bitvector::*;

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

