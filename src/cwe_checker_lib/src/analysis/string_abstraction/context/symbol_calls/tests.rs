use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Debug;

use petgraph::graph::NodeIndex;
use regex::{Match, Regex};

use super::Context;
use crate::abstract_domain::{
    AbstractDomain, CharacterInclusionDomain, CharacterSet, DataDomain, DomainInsertion, HasTop,
    Interval, IntervalDomain, PointerDomain,
};
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::analysis::pointer_inference::State as PiState;
use crate::analysis::string_abstraction::state::State;
use crate::analysis::string_abstraction::tests::mock_project::*;
use crate::intermediate_representation::{Bitvector, Datatype, ExternSymbol, Project, Sub};
use crate::{
    abstract_domain::{AbstractIdentifier, AbstractLocation},
    intermediate_representation::{Arg, ByteSize, Tid, Variable},
    utils::{binary::RuntimeMemoryImage, symbol_utils::get_symbol_map},
};

struct Setup<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String> + Debug> {
    context: Context<'a, T>,
    pi_state_before_symbol_call: PiState,
    state_before_call: State<T>,
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
            .get(0)
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
            &pi_context.runtime_memory_image,
        );

        let state_before_call: State<T> = State::mock_with_given_pi_state(
            pi_context.project.program.term.subs.get(0).unwrap().clone(),
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
        ],
    )
}

#[test]
fn test_handle_string_symbol_calls() {}

#[test]
fn test_handle_scanf_calls() {
    let scanf_symbol = ExternSymbol::mock_scanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(scanf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_scanf_calls(&setup.state_before_call, &scanf_symbol);

    let top_value = CharacterInclusionDomain::from("".to_string()).top();

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x74).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x5e).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x4c).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x38).into(),
        )));

    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x74 as i64))
            .unwrap(),
        top_value,
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x5e as i64))
            .unwrap(),
        top_value,
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x4c as i64))
            .unwrap(),
        top_value,
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x38 as i64))
            .unwrap(),
        top_value,
    );
}

#[test]
fn test_create_abstract_domain_entries_for_function_return_values_with_known_values() {
    let r2_reg = Variable::mock("r2", 4);
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![true, true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();

    let register_arg = Arg::Register {
        var: r2_reg.clone(),
        data_type: Some(Datatype::Pointer),
    };
    let stack_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Pointer),
    };
    arg_to_value_map.insert(register_arg, Some("a".to_string()));
    arg_to_value_map.insert(stack_arg, Some("b".to_string()));

    setup
        .context
        .create_abstract_domain_entries_for_function_return_values(
            &setup.pi_state_before_symbol_call,
            &mut setup.state_before_call,
            arg_to_value_map,
        );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&(-0x7c as i64))
            .unwrap(),
        CharacterInclusionDomain::from("a".to_string())
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&(-0x92 as i64))
            .unwrap(),
        CharacterInclusionDomain::from("b".to_string())
    );

    assert!(setup
        .state_before_call
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x7c).into(),
        )));

    assert!(setup
        .state_before_call
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x92).into(),
        )));
}

#[test]
fn test_add_new_string_abstract_domain() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let mut state = State::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );
    let stack_pointer = PointerDomain::new(
        stack_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        &stack_pointer,
        CharacterInclusionDomain::from("Hello World".to_string()),
    );

    assert!(state.get_stack_offset_to_string_map().contains_key(&0));

    state.set_all_maps_empty();

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("r5", 4)).unwrap(),
    );

    let heap_pointer = PointerDomain::new(
        heap_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        &heap_pointer,
        CharacterInclusionDomain::Top,
    );

    assert!(state.get_heap_to_string_map().contains_key(&heap_id));
}

#[test]
fn test_create_abstract_domain_entries_for_function_return_values_with_unknown_values() {
    let r1_reg = Variable::mock("r1", 4);
    let scanf_symbol = ExternSymbol::mock_scanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(scanf_symbol.clone(), vec![false])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();
    let register_arg = Arg::Register {
        var: r1_reg.clone(),
        data_type: Some(Datatype::Pointer),
    };
    let stack_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Pointer),
    };
    arg_to_value_map.insert(register_arg, None);
    arg_to_value_map.insert(stack_arg, None);

    setup
        .context
        .create_abstract_domain_entries_for_function_return_values(
            &setup.pi_state_before_symbol_call,
            &mut setup.state_before_call,
            arg_to_value_map,
        );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&(-0x74 as i64))
            .unwrap(),
        CharacterInclusionDomain::Top
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&(-0x38 as i64))
            .unwrap(),
        CharacterInclusionDomain::Top
    );

    assert!(setup
        .state_before_call
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x74).into(),
        )));

    assert!(setup
        .state_before_call
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x38).into(),
        )));
}

#[test]
fn test_map_source_string_parameters_to_return_arguments() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();
    let r2_arg = Arg::Register {
        var: Variable::mock("r2", 4),
        data_type: Some(Datatype::Pointer),
    };
    let r3_arg = Arg::Register {
        var: Variable::mock("r3", 4),
        data_type: Some(Datatype::Pointer),
    };
    let stack_arg_1 = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Pointer),
    };
    let stack_arg_2 = Arg::Stack {
        offset: 4,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Pointer),
    };

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![true, true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);
    let mut expected_arg_value_map: Vec<(Arg, Option<String>)> = Vec::new();
    expected_arg_value_map.push((r2_arg, Some("str1".to_string())));
    expected_arg_value_map.push((r3_arg, Some("str2".to_string())));
    expected_arg_value_map.push((stack_arg_1, Some("str3".to_string())));
    expected_arg_value_map.push((stack_arg_2, Some("str4".to_string())));
    expected_arg_value_map
        .sort_by(|(_, s1), (_, s2)| s1.clone().unwrap().cmp(&s2.clone().unwrap()));

    let mut result_arg_value_map = setup
        .context
        .map_source_string_parameters_to_return_arguments(
            &setup.pi_state_before_symbol_call,
            &sscanf_symbol,
            "str1 str2 str3 str4",
        )
        .unwrap()
        .into_iter()
        .collect::<Vec<(Arg, Option<String>)>>();

    result_arg_value_map.sort_by(|(_, s1), (_, s2)| s1.clone().unwrap().cmp(&s2.clone().unwrap()));

    assert_eq!(expected_arg_value_map, result_arg_value_map);
}

#[test]
fn test_handle_sscanf_calls_unknown_source_unknown_format() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![false, false])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

    assert!(new_state.get_stack_offset_to_string_map().is_empty());
    assert!(new_state.get_unassigned_return_pointer().is_empty());
}

#[test]
fn test_handle_sscanf_calls_known_source_unknown_format() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![true, false])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

    assert!(new_state.get_unassigned_return_pointer().is_empty());
    assert!(new_state.get_stack_offset_to_string_map().is_empty());
}

#[test]
fn test_handle_sscanf_calls_unknown_source_known_format() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![false, true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let new_state = setup
        .context
        .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x7c as i64))
            .unwrap(),
        CharacterInclusionDomain::Top
    );

    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x92 as i64))
            .unwrap(),
        CharacterInclusionDomain::Top
    );

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x7c).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x92).into(),
        )));
}

#[test]
fn test_handle_sscanf_calls_known_source_known_format() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![true, true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let new_state = setup
        .context
        .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x7c as i64))
            .unwrap(),
        CharacterInclusionDomain::from("str1".to_string())
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x68 as i64))
            .unwrap(),
        CharacterInclusionDomain::from("str2".to_string())
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x92 as i64))
            .unwrap(),
        CharacterInclusionDomain::from("str3".to_string())
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x84 as i64))
            .unwrap(),
        CharacterInclusionDomain::from("str4".to_string())
    );

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x7c).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x68).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x92).into(),
        )));

    assert!(new_state
        .get_unassigned_return_pointer()
        .contains(&PointerDomain::new(
            stack_id.clone(),
            Bitvector::from_i32(-0x84).into(),
        )));
}

#[test]
fn test_create_string_domain_for_sprintf_snprintf() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['t', 'o', 'W', 'a', 'c', 'l', ' ', 'd', 'r', 'e', 'H']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    assert_eq!(
        expected_domain,
        setup.context.create_string_domain_for_sprintf_snprintf(
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call,
            &sprintf_symbol,
            "cat %s %s %s %s".to_string(),
        )
    );
}

#[test]
fn test_no_specifiers() {
    // Test Case 1: No specifiers in format string.
    assert!(!Context::<CharacterInclusionDomain>::no_specifiers(
        "%s".to_string()
    ));
    // Test Case 2: Specifiers in format string.
    assert!(Context::<CharacterInclusionDomain>::no_specifiers(
        "hello".to_string()
    ));
}

#[test]
fn test_create_string_domain_using_constants_and_sub_domains() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let string_arg = Arg::Register {
        var: Variable::mock("r6", 4),
        data_type: Some(Datatype::Pointer),
    };
    let integer_arg = Arg::Register {
        var: Variable::mock("r7", 4),
        data_type: Some(Datatype::Integer),
    };
    let char_arg = Arg::Register {
        var: Variable::mock("r8", 4),
        data_type: Some(Datatype::Char),
    };

    let var_args: Vec<Arg> = vec![string_arg, integer_arg, char_arg];
    let format_string = "cat %s > %d %c";

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r6", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u64(0x3002),
            Bitvector::from_u64(0x3002),
        )),
    );

    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r7", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u64(2),
            Bitvector::from_u64(2),
        )),
    );

    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r8", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u64(0x42),
            Bitvector::from_u64(0x42),
        )),
    );

    let result_domain = setup
        .context
        .create_string_domain_using_constants_and_sub_domains(
            format_string.to_string(),
            &var_args,
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call,
        );

    assert_eq!(
        CharacterInclusionDomain::from("cat >HeloWrd2B".to_string()),
        result_domain
    )
}

#[test]
fn test_fetch_constant_or_domain_for_format_specifier() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let string_arg = Arg::Register {
        var: Variable::mock("r6", 4),
        data_type: Some(Datatype::Pointer),
    };
    let integer_arg = Arg::Register {
        var: Variable::mock("r7", 4),
        data_type: Some(Datatype::Integer),
    };
    let char_arg = Arg::Register {
        var: Variable::mock("r8", 4),
        data_type: Some(Datatype::Char),
    };

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(BTreeSet::new()),
        CharacterSet::Value("-0123456789".chars().collect()),
    ));

    // Test Case 1: Integer and no tracked value.
    assert_eq!(
        expected_domain,
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &integer_arg,
            "%d".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    // Test Case 2: String and no tracked value.
    assert_eq!(
        CharacterInclusionDomain::Top,
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &string_arg,
            "%S".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    // Test Case 3: Char and no tracked value.
    assert_eq!(
        CharacterInclusionDomain::Top,
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &char_arg,
            "%c".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    // Test Case 4: Integer and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r7", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u64(2),
            Bitvector::from_u64(2),
        )),
    );

    assert_eq!(
        CharacterInclusionDomain::from("2".to_string()),
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &integer_arg,
            "%d".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    // Test Case 5: Char and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r8", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u32(0x42),
            Bitvector::from_u32(0x42),
        )),
    );

    assert_eq!(
        CharacterInclusionDomain::from("B".to_string()),
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &char_arg,
            "%c".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    // Test Case 6: String and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &Variable::mock("r6", 4),
        DataDomain::Value(IntervalDomain::new(
            Bitvector::from_u32(0x3002),
            Bitvector::from_u32(0x3002),
        )),
    );

    assert_eq!(
        CharacterInclusionDomain::from("Hello World".to_string()),
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &string_arg,
            "%s".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let mut pointer: PointerDomain<IntervalDomain> = PointerDomain::new(
        stack_id,
        IntervalDomain::new(Bitvector::from_i32(16), Bitvector::from_i32(16)),
    );

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("r9", 4)).unwrap(),
    );

    pointer.add_target(
        heap_id.clone(),
        IntervalDomain::new(Bitvector::from_i32(0), Bitvector::from_i32(0)),
    );

    setup
        .state_before_call
        .add_new_stack_offset_to_string_entry(16, CharacterInclusionDomain::from("a".to_string()));
    setup
        .state_before_call
        .add_new_heap_to_string_entry(heap_id, CharacterInclusionDomain::from("b".to_string()));

    // Test Case 5: String and tracked domain.
    setup
        .pi_state_before_symbol_call
        .set_register(&Variable::mock("r6", 4), DataDomain::Pointer(pointer));

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(BTreeSet::new()),
        CharacterSet::Value("ab".chars().collect()),
    ));

    assert_eq!(
        expected_domain,
        setup.context.fetch_constant_or_domain_for_format_specifier(
            &string_arg,
            "%s".to_string(),
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call
        )
    );
}

#[test]
fn test_merge_domains_from_multiple_pointer_targets() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("r5", 4)).unwrap(),
    );

    let mut domain_pointer: PointerDomain<IntervalDomain> =
        PointerDomain::new(stack_id.clone(), Bitvector::from_i32(0).into());

    // Test Case 1: Single stack pointer with single target and no domain.
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer,
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
            &domain_pointer,
        );

    assert_eq!(
        CharacterInclusionDomain::from("a".to_string()),
        returned_domain
    );

    // Test Case 3: Stack and Heap pointer with two targets and only one points to a domain.
    domain_pointer.add_target(heap_id.clone(), Bitvector::from_i32(0).into());
    let returned_domain =
        Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &domain_pointer,
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
            &domain_pointer,
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
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup.context.handle_sprintf_and_snprintf_calls(
        &setup.state_before_call,
        &sprintf_symbol,
    );

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
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup.context.handle_sprintf_and_snprintf_calls(
        &setup.state_before_call,
        &sprintf_symbol,
    );

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
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

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
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

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
fn test_handle_strcat_and_strncat_calls_with_known_second_input() {
    let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(strcat_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['s', 't', 'r', ' ', '1', '2', '3', '4']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    let new_state = setup
        .context
        .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

    assert_eq!(
        expected_domain,
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x3c as i64))
            .unwrap()
    );
}

#[test]
fn test_handle_strcat_and_strncat_calls_with_unknown_second_input() {
    let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(strcat_symbol.clone(), vec![false])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    // Test Case 1: No string domain is tracked for the second input.
    let new_state = setup
        .context
        .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

    assert_eq!(
        CharacterInclusionDomain::Top,
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x3c as i64))
            .unwrap()
    );

    // Test Case 2: A string domain is tracked for the second input.
    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(vec!['a'].into_iter().collect()),
        CharacterSet::Top,
    ));

    setup
        .state_before_call
        .add_new_stack_offset_to_string_entry(
            0x28,
            CharacterInclusionDomain::from("a".to_string()),
        );

    let new_state = setup
        .context
        .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

    assert_eq!(
        expected_domain,
        *new_state
            .get_stack_offset_to_string_map()
            .get(&(-0x3c as i64))
            .unwrap()
    );
}

#[test]
fn test_handle_free() {
    let free_symbol = ExternSymbol::mock_free_symbol_arm();
    let malloc_symbol = ExternSymbol::mock_malloc_symbol_arm();
    let r0_reg = Variable::mock("r0", 4);
    let project = mock_project_with_intraprocedural_control_flow(
        vec![
            (malloc_symbol.clone(), vec![]),
            (free_symbol.clone(), vec![]),
        ],
        "func",
    );

    let extern_subs: HashSet<Tid> = vec![malloc_symbol.tid, free_symbol.clone().tid]
        .into_iter()
        .collect();
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, extern_subs);
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

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
