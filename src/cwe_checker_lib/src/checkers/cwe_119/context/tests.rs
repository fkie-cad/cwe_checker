use super::*;

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
    let mut malloc_state = PiState::new(&Variable::mock("RSP", 8), Tid::new("func"));
    malloc_state.set_register(&Variable::mock("RDI", 8), Bitvector::from_i64(3).into());
    *pi_results.get_mut_states_at_tids() = HashMap::from([(Tid::new("malloc_call"), malloc_state)]);
    let malloc_symbol = ExternSymbol::mock_x64("malloc");

    assert_eq!(
        compute_size_value_of_malloc_like_call(
            &Tid::new("malloc_call"),
            &malloc_symbol,
            &pi_results
        )
        .unwrap(),
        Bitvector::from_i64(3).into()
    );
    assert!(compute_size_value_of_malloc_like_call(
        &Tid::new("other"),
        &ExternSymbol::mock_x64("other"),
        &pi_results
    )
    .is_none());
}

#[test]
fn test_substitute_param_values_context_sensitive() {
    let mut context = Context::mock_x64();
    let param_id = AbstractIdentifier::mock("func", "RDI", 8);
    let callsite_id = AbstractIdentifier::mock("callsite_id", "RDI", 8);

    let recursive_param_id = AbstractIdentifier::mock("main", "RSI", 8);
    let recursive_callsite_id = AbstractIdentifier::mock("recursive_callsite_id", "RSI", 8);

    let param_value = Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(1).into());
    let recursive_param_value = Data::from(Bitvector::from_i64(41));
    let param_replacement_map = HashMap::from([
        (callsite_id, param_value.clone()),
        (recursive_callsite_id.clone(), recursive_param_value),
    ]);
    let callee_to_callsites_map = HashMap::from([
        (Tid::new("func"), HashSet::from([Tid::new("callsite_id")])),
        (
            Tid::new("main"),
            HashSet::from([Tid::new("recursive_callsite_id")]),
        ),
    ]);
    let call_to_caller_map = HashMap::from([
        (Tid::new("callsite_id"), Tid::new("main")),
        (
            Tid::new("recursive_callsite_id"),
            Tid::new("somer_other_fn_id"),
        ),
    ]);
    context.param_replacement_map = param_replacement_map;
    context.callee_to_callsites_map = callee_to_callsites_map;
    context.call_to_caller_fn_map = call_to_caller_map;
    // non-recursive substitution
    let result = context.substitute_param_values_context_sensitive(
        &Data::from_target(param_id.clone(), Bitvector::from_i64(5).into()),
        &Tid::new("callsite_id"),
        &Tid::new("func"),
    );
    assert_eq!(
        result,
        Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(6).into())
    );
    // recursive substitution
    let result = context.recursively_substitute_param_values_context_sensitive(
        &Data::from_target(param_id, Bitvector::from_i64(5).into()),
        &Tid::new("func"),
        &[Tid::new("callsite_id"), Tid::new("recursive_callsite_id")],
    );
    println!("{:#}", result.to_json_compact());
    assert_eq!(result, Bitvector::from_i64(47).into());
}

#[test]
fn test_substitute_param_values() {
    let mut context = Context::mock_x64();
    let param_id = AbstractIdentifier::mock("func", "RDI", 8);
    let callsite_id = AbstractIdentifier::mock("callsite_id", "RDI", 8);

    let recursive_param_id = AbstractIdentifier::mock("main", "RSI", 8);
    let recursive_callsite_id = AbstractIdentifier::mock("recursive_callsite_id", "RSI", 8);

    let param_value = Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(1).into());
    let recursive_param_value = Data::from(Bitvector::from_i64(39));
    let param_replacement_map = HashMap::from([
        (callsite_id, param_value.clone()),
        (recursive_callsite_id.clone(), recursive_param_value),
    ]);
    let callee_to_callsites_map = HashMap::from([
        (Tid::new("func"), HashSet::from([Tid::new("callsite_id")])),
        (
            Tid::new("main"),
            HashSet::from([Tid::new("recursive_callsite_id")]),
        ),
    ]);
    context.param_replacement_map = param_replacement_map;
    context.callee_to_callsites_map = callee_to_callsites_map;
    // non-recursive substitution
    let (result_absolute, result) = context.substitute_param_values(&param_id);
    assert!(result_absolute.is_none());
    assert_eq!(result, param_value);
    // recursive substitution
    let result = context.recursively_substitute_param_values(&Data::from_target(
        param_id,
        Bitvector::from_i64(5).into(),
    ));
    assert_eq!(result, Bitvector::from_i64(45).into());
}
