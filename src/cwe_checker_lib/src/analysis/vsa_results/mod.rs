use crate::intermediate_representation::{Expression, Arg};
use crate::prelude::*;

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

    /// Evaluate the value of the given expression at the given jump instruction.
    fn eval_at_jmp(&self, jmp_tid: &Tid, expression: &Expression) -> Option<Self::ValueDomain>;
}
