use std::collections::HashMap;
use std::fmt::Debug;

use petgraph::graph::NodeIndex;

use super::Context;
use crate::abstract_domain::{
    AbstractDomain, CharacterInclusionDomain, CharacterSet, DataDomain, DomainInsertion, HasTop,
    IntervalDomain,
};
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::analysis::pointer_inference::State as PiState;
use crate::analysis::string_abstraction::state::State;
use crate::analysis::string_abstraction::tests::*;
use crate::intermediate_representation::*;
use crate::variable;
use crate::{
    abstract_domain::{AbstractIdentifier, AbstractLocation},
    utils::symbol_utils::get_symbol_map,
};

pub struct Setup<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug> {
    pub context: Context<'a, T>,
    pub pi_state_before_symbol_call: PiState,
    pub state_before_call: State<T>,
}

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug> Setup<'a, T> {
    pub fn new(pi_results: &'a PointerInferenceComputation<'a>) -> Self {
        let mut pi_state = pi_results
            .get_node_value(NodeIndex::new(0))
            .unwrap()
            .unwrap_value()
            .clone();

        let pi_context = pi_results.get_context();

        // Get the pi state right before the call.
        for def in pi_context
            .project
            .program
            .term
            .subs
            .values()
            .next()
            .unwrap()
            .term
            .blocks
            .get(0)
            .unwrap()
            .term
            .defs
            .iter()
        {
            pi_state = pi_context.update_def(&pi_state, def).unwrap();
        }

        let context: Context<T> = Context::mock(
            &pi_context.project,
            mock_string_symbol_map(&pi_context.project),
            mock_format_index_map(),
            &pi_results,
        );

        let state_before_call: State<T> = State::mock_with_given_pi_state(
            pi_context
                .project
                .program
                .term
                .subs
                .values()
                .next()
                .unwrap()
                .clone(),
            pi_state.clone(),
        );

        Setup {
            context,
            pi_state_before_symbol_call: pi_state,
            state_before_call,
        }
    }
}

fn mock_format_index_map() -> HashMap<String, usize> {
    let mut map: HashMap<String, usize> = HashMap::new();
    map.insert("sprintf".to_string(), 1);
    map.insert("scanf".to_string(), 0);
    map.insert("sscanf".to_string(), 1);

    map
}

fn mock_string_symbol_map(project: &Project) -> HashMap<Tid, &ExternSymbol> {
    get_symbol_map(
        project,
        &[
            "sprintf".to_string(),
            "scanf".to_string(),
            "sscanf".to_string(),
            "strcat".to_string(),
            "memcpy".to_string(),
        ],
    )
}

#[test]
fn test_handle_generic_symbol_calls() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    setup.state_before_call.add_new_variable_to_pointer_entry(
        variable!("r1:4"),
        DataDomain::from(IntervalDomain::from(Bitvector::from_i32(32))),
    );

    let new_state = setup
        .context
        .handle_generic_symbol_calls(&memcpy_symbol, &mut setup.state_before_call);

    assert!(new_state.get_variable_to_pointer_map().is_empty());
}

#[test]
fn test_handle_unknown_symbol_calls() {
    let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(memcpy_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    setup.state_before_call.add_new_variable_to_pointer_entry(
        variable!("r1:4"),
        DataDomain::from(IntervalDomain::from(Bitvector::from_i32(32))),
    );

    setup
        .context
        .handle_unknown_symbol_calls(&mut setup.state_before_call);

    assert!(setup
        .state_before_call
        .get_variable_to_pointer_map()
        .is_empty());
}

#[test]
fn test_add_new_string_abstract_domain() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let mut state = State::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );
    let stack_pointer = DataDomain::from_target(
        stack_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        &stack_pointer.get_relative_values(),
        CharacterInclusionDomain::from("Hello World".to_string()),
    );

    assert!(state.get_stack_offset_to_string_map().contains_key(&0));

    state.set_all_maps_empty();

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
    );

    let heap_pointer = DataDomain::from_target(
        heap_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        &heap_pointer.get_relative_values(),
        CharacterInclusionDomain::Top,
    );

    assert!(state.get_heap_to_string_map().contains_key(&heap_id));
}

#[test]
fn test_merge_domains_from_multiple_pointer_targets() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
    );

    let mut domain_pointer: DataDomain<IntervalDomain> =
        DataDomain::from_target(stack_id.clone(), Bitvector::from_i32(0).into());

    // Test Case 1: Single stack pointer with single target and no domain.
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer.get_relative_values(),
        );

    assert_eq!(CharacterInclusionDomain::Top, returned_domain);

    // Test Case 2: Single stack pointer with a domain.
    setup
        .state_before_call
        .add_new_stack_offset_to_string_entry(0, CharacterInclusionDomain::from("a".to_string()));
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer.get_relative_values(),
        );

    assert_eq!(
        CharacterInclusionDomain::from("a".to_string()),
        returned_domain
    );

    // Test Case 3: Stack and Heap pointer with two targets and only one points to a domain.
    domain_pointer.insert_relative_value(heap_id.clone(), Bitvector::from_i32(0).into());
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer.get_relative_values(),
        );

    assert_eq!(CharacterInclusionDomain::Top, returned_domain);

    // Test Case 4: Stack and Heap pointer with two targets and both point to different domains.
    setup
        .state_before_call
        .add_new_heap_to_string_entry(heap_id, CharacterInclusionDomain::from("b".to_string()));
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer.get_relative_values(),
        );

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(vec![].into_iter().collect()),
        CharacterSet::Value(vec!['a', 'b'].into_iter().collect()),
    ));

    assert_eq!(expected_domain, returned_domain);
}

#[test]
fn test_handle_sprintf_and_snprintf_calls_known_format_string() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_sprintf_and_snprintf_calls(&setup.state_before_call, &sprintf_symbol);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['t', 'o', 'W', 'a', 'c', 'l', ' ', 'd', 'r', 'e', 'H']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x54 as i64))
            .unwrap(),
        expected_domain,
    );
}

#[test]
fn test_handle_sprintf_and_snprintf_calls_unknown_format_string() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![false])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_sprintf_and_snprintf_calls(&setup.state_before_call, &sprintf_symbol);

    assert_eq!(
        CharacterInclusionDomain::Top,
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x54 as i64))
            .unwrap()
    );
}

#[test]
fn test_insert_constant_integer_into_format_string() {
    let string_with_insertion =
        Context::<CharacterInclusionDomain>::get_constant_integer_domain(Bitvector::from_u32(2));

    assert_eq!(
        CharacterInclusionDomain::from("2".to_string()),
        string_with_insertion.unwrap()
    );
}

#[test]
fn test_insert_constant_char_into_format_string() {
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(ExternSymbol::mock_sprintf_symbol_arm(), vec![false])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    // Test Case 1: Char is given as a hex constant in a register or stack position
    let string_with_insertion = setup
        .context
        .get_constant_char_domain(Bitvector::from_u32(0x42));

    assert_eq!(
        CharacterInclusionDomain::from("B".to_string()),
        string_with_insertion.unwrap()
    );

    // Test Case 2: Char is contained in the binary's read-only memory.
    let string_with_insertion = setup
        .context
        .get_constant_char_domain(Bitvector::from_u32(0x3002));

    assert_eq!(
        CharacterInclusionDomain::from("H".to_string()),
        string_with_insertion.unwrap()
    );
}

#[test]
fn test_insert_constant_string_into_format_string() {
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(ExternSymbol::mock_sprintf_symbol_arm(), vec![false])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    // Test Case 1: String contained in read-only memory.
    let string_with_insertion = setup
        .context
        .get_constant_string_domain(Bitvector::from_u32(0x3002));

    assert_eq!(
        CharacterInclusionDomain::from("Hello World".to_string()),
        string_with_insertion.unwrap()
    );
}

#[test]
fn test_handle_free() {
    let free_symbol = ExternSymbol::mock_free_symbol_arm();
    let malloc_symbol = ExternSymbol::mock_malloc_symbol_arm();
    let r0_reg = variable!("r0:4");
    let project = mock_project_with_intraprocedural_control_flow(
        vec![
            (malloc_symbol.clone(), vec![]),
            (free_symbol.clone(), vec![]),
        ],
        "func",
    );

    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let object_id = AbstractIdentifier::new(
        Tid::new("func_malloc_0"),
        AbstractLocation::from_var(&r0_reg).unwrap(),
    );

    setup
        .state_before_call
        .add_new_heap_to_string_entry(object_id.clone(), CharacterInclusionDomain::Top);

    setup.state_before_call.set_pointer_inference_state(Some(
        pi_results
            .get_node_value(NodeIndex::new(2))
            .unwrap()
            .unwrap_value()
            .clone(),
    ));

    let new_state = setup
        .context
        .handle_free(&setup.state_before_call, &free_symbol);

    assert!(!new_state.get_heap_to_string_map().contains_key(&object_id));
}
