use std::collections::HashMap;

use crate::{
    abstract_domain::{AbstractDomain, AbstractIdentifier, MemRegion},
    analysis::pointer_inference::State as PointerInferenceState,
    intermediate_representation::Variable,
    prelude::*,
};

use super::Taint;

#[derive(Serialize, Deserialize, Debug, Eq, Clone)]
pub struct State {
    /// The set of currently tainted registers.
    register_taint: HashMap<Variable, Taint>,
    /// The Taint contained in memory objects
    memory_taint: HashMap<AbstractIdentifier, MemRegion<Taint>>,
    /// The state of the pointer inference analysis.
    /// Used only for preventing unneccessary recomputation during handling of `Def`s in a basic block.
    /// It is set when handling `Def`s (except for the first `Def` in a block)
    /// provided that a corresponding pointer inference analysis state exists.
    /// Otherwise the field is ignored (including in the [merge](State::merge)-function) and usually set to `None`.
    #[serde(skip_serializing)]
    pointer_inference_state: Option<PointerInferenceState>,
}

impl PartialEq for State {
    /// Two states are equal if the same values are tainted in both states.
    ///
    /// The equality operator ignores the `pointer_inference_state` field,
    /// since it only denotes an intermediate value.
    fn eq(&self, other: &Self) -> bool {
        self.register_taint == other.register_taint && self.memory_taint == other.memory_taint
    }
}

impl AbstractDomain for State {}

impl State {}
