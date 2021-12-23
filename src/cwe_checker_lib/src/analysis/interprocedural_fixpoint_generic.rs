//! Types and functions shared between the implementations
//! of forward and backward interprocedural fixpoint computations.

use crate::prelude::*;

/// NodeValue that can either be a single abstract value or a
/// composition of the abstract value computed following an interprocedural call in the graph
/// and of the abstract value before or after the call (depending on the direction of the fixpoint analysis).
/// The CallFlowCombinator then allows for a merge of the values computed over both paths.
///
/// The call_stub value will either be transferred from the callsite to the return site
/// in a forward analysis or the other way around in a backward analysis.
///
/// The interprocedural_flow value will either be transferred from the end of the called subroutine
/// to the return site in case of a forward analysis or from the beginning of the called subroutine
/// to the callsite in a backward analysis.
#[derive(PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum NodeValue<T: PartialEq + Eq + Clone> {
    /// A single abstract value
    Value(T),
    /// The value saved at artificial combinator nodes.
    CallFlowCombinator {
        /// The value flowing through the intraprocedural edge of the corresponding call.
        call_stub: Option<T>,
        /// The value flowing through the interprocedural edge of the corresponding call,
        /// i.e. either between callsite and start of the called function
        /// or between end of the called function and the return-to site of the call.
        interprocedural_flow: Option<T>,
    },
}

impl<T: PartialEq + Eq + Clone> NodeValue<T> {
    /// Unwraps the contained value for non-combinator nodes.
    /// Panics if given a combinator value of an artificial node.
    pub fn unwrap_value(&self) -> &T {
        match self {
            NodeValue::Value(value) => value,
            _ => panic!("Unexpected node value type"),
        }
    }
}

/// Helper function to merge to values wrapped in `Option<..>`.
/// Merges `(Some(x), None)` to `Some(x)`.
pub fn merge_option<T: Clone, F>(opt1: &Option<T>, opt2: &Option<T>, merge: F) -> Option<T>
where
    F: Fn(&T, &T) -> T,
{
    match (opt1, opt2) {
        (Some(value1), Some(value2)) => Some(merge(value1, value2)),
        (Some(value), None) | (None, Some(value)) => Some(value.clone()),
        (None, None) => None,
    }
}
