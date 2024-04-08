//! This module provides the [`VsaResult`] trait
//! which defines an interface for the results of analyses similar to a value set analysis.

use crate::abstract_domain::{AbstractIdentifier, AbstractLocation};
use crate::analysis::graph::NodeIndex;
use crate::intermediate_representation::{Arg, Expression};
use crate::prelude::*;

use std::collections::BTreeMap;

/// Trait for types that provide access to the result of a value set analysis.
///
/// The generic type parameter can be used to implement this trait multiple
/// times, i.e., the same type can  provide access to VSA results with
/// different value domains.
// NOTE: We can not implement `AsRef` on the type instead since `impl Trait` is
// only allowed in function parameters and return types, not generic type
// parameters or trait bounds.
pub trait HasVsaResult<T> {
    /// Converts a reference to `Self` into a reference to a type that implements
    /// [`VsaResult`] with [`ValueDomain`] `T`.
    ///
    /// [`ValueDomain`]: VsaResult::ValueDomain
    fn vsa_result(&self) -> &impl VsaResult<ValueDomain = T>;
}

/// A trait providing an interface for accessing the results of a value set analysis.
/// Note that the returned values may be any type of information associated with values at certain program points,
/// i.e. the trait can also be used for other analyses than just value set analyses.
///
/// Every returned value is wrapped into an `Option<..>`.
/// This should mainly be used to indicate that the analysis did not compute a value at a certain point,
/// e.g. because the code point was deemed to be dead code.
/// If the analysis wants to indicate that no specific information is known about a certain value
/// then this should be encoded in the `ValueDomain` itself instead of returning `None`.
pub trait VsaResult {
    /// The type of the returned values.
    /// Usually this should be an [`AbstractDomain`](crate::abstract_domain::AbstractDomain),
    /// although this is not strictly required.
    type ValueDomain;

    /// Return the value stored for write instructions, the value read for read instructions or the value assigned for assignments.
    fn eval_value_at_def(&self, def_tid: &Tid) -> Option<Self::ValueDomain>;

    /// Return the value of the address where something is read or written for read or store instructions.
    fn eval_address_at_def(&self, def_tid: &Tid) -> Option<Self::ValueDomain>;

    /// Return the value of a parameter at the given jump instruction.
    fn eval_parameter_arg_at_call(&self, jmp_tid: &Tid, param: &Arg) -> Option<Self::ValueDomain>;

    /// Return the value of a parameter at the given jump instruction.
    fn eval_parameter_location_at_call(
        &self,
        jmp_tid: &Tid,
        param: &AbstractLocation,
    ) -> Option<Self::ValueDomain>;

    /// Evaluate the value of the given expression at the given jump instruction.
    fn eval_at_jmp(&self, jmp_tid: &Tid, expression: &Expression) -> Option<Self::ValueDomain>;

    /// Evaluate the given expression at the given node of the graph that the
    /// value set analysis was computed on.
    fn eval_at_node(&self, node: NodeIndex, expression: &Expression) -> Option<Self::ValueDomain>;

    /// Returns the mapping of abstract identfiers in the callee to values in
    /// the caller for the given call.
    fn get_call_renaming_map(
        &self,
        _call: &Tid,
    ) -> Option<&BTreeMap<AbstractIdentifier, Self::ValueDomain>> {
        None
    }
}
