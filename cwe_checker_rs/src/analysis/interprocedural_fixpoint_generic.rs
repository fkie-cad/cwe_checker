use crate::prelude::*;

/// NodeValue that can either be a simple value or a
/// combination of two values representing a fall through
/// and interprocedural flow value
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeValue<T: PartialEq + Eq> {
    Value(T),
    CallFlowCombinator { call_stub: Option<T>, interprocedural_flow: Option<T> },
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