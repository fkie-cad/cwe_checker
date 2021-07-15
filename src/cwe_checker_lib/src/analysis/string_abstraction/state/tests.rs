use super::*;
use crate::analysis::pointer_inference::State as PiState;

impl<T: AbstractDomain + HasTop + Eq + From<String>> State<T> {
    pub fn mock_with_default_pi_state(current_sub: Term<Sub>) -> Self {
        let pi_state =
            PointerInferenceState::new(&Variable::mock("sp", 4 as u64), current_sub.tid.clone());
        State {
            unassigned_return_pointer: HashSet::new(),
            variable_to_pointer_map: HashMap::new(),
            stack_offset_to_pointer_map: HashMap::new(),
            stack_offset_to_string_map: HashMap::new(),
            heap_to_string_map: HashMap::new(),
            current_sub: Some(current_sub),
            pointer_inference_state: Some(pi_state),
        }
    }

    pub fn mock_with_given_pi_state(current_sub: Term<Sub>, pi_state: PiState) -> Self {
        State {
            unassigned_return_pointer: HashSet::new(),
            variable_to_pointer_map: HashMap::new(),
            stack_offset_to_pointer_map: HashMap::new(),
            stack_offset_to_string_map: HashMap::new(),
            heap_to_string_map: HashMap::new(),
            current_sub: Some(current_sub),
            pointer_inference_state: Some(pi_state),
        }
    }

    pub fn set_all_maps_empty(&mut self) {
        self.unassigned_return_pointer = HashSet::new();
        self.heap_to_string_map = HashMap::new();
        self.stack_offset_to_pointer_map = HashMap::new();
        self.stack_offset_to_string_map = HashMap::new();
        self.variable_to_pointer_map = HashMap::new();
    }

    pub fn get_unassigned_return_pointer(&self) -> &HashSet<PointerDomain<IntervalDomain>> {
        &self.unassigned_return_pointer
    }
}
