//! This module defines traits describing general properties of abstract domains
//! as well as several abstract domain types implementing these traits.

use crate::intermediate_representation::*;
use crate::prelude::*;

mod bitvector;
pub use bitvector::*;

mod identifier;
pub use identifier::*;

mod pointer;
pub use pointer::*;

mod data;
pub use data::*;

mod mem_region;
pub use mem_region::*;

mod interval;
pub use interval::*;

/// The main trait describing an abstract domain.
///
/// Each abstract domain is partially ordered.
/// Abstract domains of the same type can be merged.
pub trait AbstractDomain: Sized + Eq + Clone {
    /// Return an upper bound (with respect to the partial order on the domain) for the two inputs `self` and `other`.
    fn merge(&self, other: &Self) -> Self;

    /// Returns whether the element represents the top element (i.e. maximal with respect to the partial order) or not.
    /// If a domain has no maximal element, this function should always return false.
    fn is_top(&self) -> bool;
}

/// A trait for types representing values with a fixed size (in bytes).
///
/// For abstract domains, the bytesize is a parameter of the domain itself,
/// i.e. you cannot merge values of different bytesizes,
/// since they lie in different posets (one for each bytesize).
pub trait SizedDomain {
    /// Return the size of the represented value in bytes.
    fn bytesize(&self) -> ByteSize;

    /// Return a new top element with the given bytesize.
    /// The function is expected to panic if the type in question does not also implement the `HasTop` trait.
    fn new_top(bytesize: ByteSize) -> Self;
}

/// An abstract domain implementing this trait has a global maximum, i.e. a *Top* element.
pub trait HasTop {
    /// Return an instance of the *Top* element.
    ///
    /// Since an abstract domain type may represent a whole family of abstract domains,
    /// this function takes an instance of the domain as a parameter,
    /// so it can return the *Top* element of the same family member that the provided instance belongs to.
    fn top(&self) -> Self;
}

/// A trait for abstract domains that can represent values loaded into CPU register.
///
/// The domain implements all general operations used to manipulate register values.
/// The domain is parametrized by its bytesize (which represents the size of the register).
/// It has a *Top* element, which is only characterized by its bytesize.
pub trait RegisterDomain: AbstractDomain + SizedDomain + HasTop {
    /// Compute the (abstract) result of a binary operation
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self;

    /// Compute the (abstract) result of a unary operation
    fn un_op(&self, op: UnOpType) -> Self;

    /// Extract a sub-bitvector
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self;

    /// Perform a typecast to extend a bitvector or to cast between integer and floating point types.
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self;

    /// Return the bytesize of the result of the given binary operation.
    /// Has a generic implementation that should not be overwritten!
    fn bin_op_bytesize(&self, op: BinOpType, rhs: &Self) -> ByteSize {
        use BinOpType::*;
        match op {
            Piece => self.bytesize() + rhs.bytesize(),
            IntAdd | IntSub | IntMult | IntDiv | IntSDiv | IntRem | IntSRem | IntLeft
            | IntRight | IntSRight | IntAnd | IntOr | IntXOr | FloatAdd | FloatSub | FloatMult
            | FloatDiv => self.bytesize(),
            IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual
            | IntCarry | IntSCarry | IntSBorrow | BoolAnd | BoolOr | BoolXOr | FloatEqual
            | FloatNotEqual | FloatLess | FloatLessEqual => ByteSize::new(1),
        }
    }
}

/// A conversion trait for abstract domains that can represent register values.
pub trait TryToBitvec {
    /// If `self` represents a single absolute value, return it.
    /// In all other cases return an error.
    fn try_to_bitvec(&self) -> Result<Bitvector, Error>;

    /// If `self` represents a single absolute value, try to convert it to a signed integer and return it.
    /// Else return an error.
    /// Note that the conversion loses information about the bytesize of the value.
    fn try_to_offset(&self) -> Result<i64, Error> {
        Ok(self.try_to_bitvec()?.try_to_i64()?)
    }
}

/// A conversion trait for abstract domains that can represent register values.
pub trait TryToInterval {
    /// If `self` represents an interval of absolute values (or can be widened to represent such an interval)
    /// then return it if the interval is bounded.
    /// For unbounded (i.e. `Top`) intervals or if the abstract value does not represent absolute values return an error.
    fn try_to_interval(&self) -> Result<Interval, Error>;

    /// If `self` represents an interval of absolute values (or can be widened to represent such an interval)
    /// then return it as an interval of signed integers if the interval is bounded.
    /// Else return an error.
    /// Note that the conversion loses information about the bytesize of the values contained in the interval.
    fn try_to_offset_interval(&self) -> Result<(i64, i64), Error> {
        let interval = self.try_to_interval()?;
        Ok((interval.start.try_to_i64()?, interval.end.try_to_i64()?))
    }
}
