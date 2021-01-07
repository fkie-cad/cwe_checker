use crate::prelude::*;

/// NodeValue that can either be a single abstract value or a
/// composition of the abstract value computed following an interprocedural
/// call in the graph and of the abstract value when the call is not taken.
/// The CallFlowCombinator then allows for a merge of the values computed
/// over both paths.
///
/// The call_stub value will either be transferred from the callsite to the return site
/// in a forward analysis or the other way around in a backward analysis.
///
/// The interprocedural_flow value will either be transferred from the end of the called subroutine
/// to the return site in case of a forward analysis or from the beginning of the called subroutine
/// to the callsite in a backward analysis.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeValue<T: PartialEq + Eq> {
    Value(T),
    CallFlowCombinator {
        call_stub: Option<T>,
        interprocedural_flow: Option<T>,
    },
}

impl<T: PartialEq + Eq> NodeValue<T> {
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
