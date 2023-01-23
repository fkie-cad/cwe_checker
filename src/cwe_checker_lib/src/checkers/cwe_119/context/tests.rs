use super::*;
use crate::{bitvec, variable};
use std::collections::BTreeSet;

impl<'a> Context<'a> {
    /// Create a mock context.
    /// Note that this function leaks memory!
    pub fn mock_x64() -> Context<'static> {
        let mut project = Box::new(Project::mock_x64());
        project.program.term.subs = BTreeMap::from([
            (Tid::new("func"), Sub::mock("func")),
            (Tid::new("main"), Sub::mock("main")),
        ]);
        let project = Box::leak(project);
        let pointer_inference = Box::new(PointerInference::mock(project));
        let pointer_inference = Box::leak(pointer_inference);
        let analysis_results = AnalysisResults::mock_from_project(project);
        let analysis_results =
            Box::new(analysis_results.with_pointer_inference(Some(pointer_inference)));
        let analysis_results = Box::leak(analysis_results);
        let (log_collector, _) = crossbeam_channel::unbounded();

        Context::new(analysis_results, log_collector)
    }
}

#[test]
fn test_compute_size_value_of_malloc_like_call() {
    use crate::analysis::pointer_inference::State as PiState;
    let project = Project::mock_x64();
    let mut pi_results = PointerInference::mock(&project);
    let mut malloc_state = PiState::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new());
    malloc_state.set_register(&variable!("RDI:8"), bitvec!("3:8").into());
    *pi_results.get_mut_states_at_tids() = HashMap::from([(Tid::new("malloc_call"), malloc_state)]);
    let malloc_symbol = ExternSymbol::mock_x64("malloc");

    assert_eq!(
        compute_size_value_of_malloc_like_call(
            &Tid::new("malloc_call"),
            &malloc_symbol,
            &pi_results
        )
        .unwrap(),
        bitvec!("3:8").into()
    );
    assert!(compute_size_value_of_malloc_like_call(
        &Tid::new("other"),
        &ExternSymbol::mock_x64("other"),
        &pi_results
    )
    .is_none());
}
