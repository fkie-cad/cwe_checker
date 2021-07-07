use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;

use super::Context;
use crate::abstract_domain::{
    AbstractDomain, CharacterInclusionDomain, HasTop, IntervalDomain, PointerDomain,
};
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::analysis::pointer_inference::State as PiState;
use crate::analysis::string_abstraction::state::State;
use crate::analysis::string_abstraction::tests::mock_project::*;
use crate::intermediate_representation::{Bitvector, ExternSymbol, Project, Sub};
use crate::{
    abstract_domain::{AbstractIdentifier, AbstractLocation},
    intermediate_representation::{Arg, ByteSize, Tid, Variable},
    utils::{binary::RuntimeMemoryImage, symbol_utils::get_symbol_map},
};

struct Setup<'a, T: AbstractDomain + HasTop + Eq + From<String>> {
    context: Context<'a, T>,
    pi_state_before_symbol_call: PiState,
    state_before_call: State<T>,
}

impl<'a, T: AbstractDomain + HasTop + Eq + From<String>> Setup<'a, T> {
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
fn test_get_abstract_id_for_function_parameter_from_register() {
    let call_tid = Tid::new("call");
    let rdi_reg = Variable::mock("r0", 4);
    let arg = Arg::Register{var: rdi_reg.clone(), data_type: None};

    let project = mock_project_with_intraprocedural_control_flow(vec![], "");
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&rdi_reg).unwrap(),
    );

    assert_eq!(
        expected_id,
        setup
            .context
            .get_abstract_id_for_function_parameter(&arg, &call_tid)
    );
}

#[test]
fn test_get_abstract_id_for_function_parameter_from_stack() {
    let call_tid = Tid::new("call");
    let sp_reg = Variable::mock("sp", 4);
    let arg = Arg::Stack {
        offset: 8,
        size: ByteSize::new(8),
        data_type: None,
    };

    let project = mock_project_with_intraprocedural_control_flow(vec![], "");
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_stack(&sp_reg, &ByteSize::new(8), &8).unwrap(),
    );

    assert_eq!(
        expected_id,
        setup
            .context
            .get_abstract_id_for_function_parameter(&arg, &call_tid)
    );
}

#[test]
fn test_handle_string_symbol_calls() {}

#[test]
fn test_handle_scanf_calls() {
    let call_tid = Tid::new("func_sprintf_0");
    let r1_reg = Variable::mock("r1", 4);
    let r2_reg = Variable::mock("r2", 4);
    let r3_reg = Variable::mock("r3", 4);
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

    let new_state =
        setup
            .context
            .handle_scanf_calls(&setup.state_before_call, &scanf_symbol, &call_tid);

    let expected_r1_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r1_reg).unwrap(),
    );

    let expected_r2_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r2_reg).unwrap(),
    );

    let expected_r3_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r3_reg).unwrap(),
    );

    let expected_stack_abstract_id = AbstractIdentifier::new(
        call_tid,
        AbstractLocation::from_stack(&Variable::mock("sp", 4), &ByteSize::new(4), &0).unwrap(),
    );

    let top_value = CharacterInclusionDomain::from("".to_string()).top();

    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_r1_abstract_id)
            .unwrap(),
        top_value
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_r2_abstract_id)
            .unwrap(),
        top_value
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_r3_abstract_id)
            .unwrap(),
        top_value
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_stack_abstract_id)
            .unwrap(),
        top_value
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x74))
            .unwrap(),
        expected_r1_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x5e))
            .unwrap(),
        expected_r2_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x4c))
            .unwrap(),
        expected_r3_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x38))
            .unwrap(),
        expected_stack_abstract_id
    );
}

#[test]
fn test_create_abstract_domain_entries_for_function_arguments_with_known_values() {
    let call_tid = Tid::new("func_sprintf_0");
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

    let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();

    let register_arg = Arg::Register{var: r2_reg.clone(), data_type: None};;
    let stack_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: None,
    };
    arg_to_value_map.insert(register_arg, Some("a".to_string()));
    arg_to_value_map.insert(stack_arg, Some("b".to_string()));

    setup
        .context
        .create_abstract_domain_entries_for_function_arguments(
            &setup.pi_state_before_symbol_call,
            &mut setup.state_before_call,
            &call_tid,
            arg_to_value_map,
        );

    let expected_r2_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r2_reg).unwrap(),
    );

    let expected_stack_abstract_id = AbstractIdentifier::new(
        call_tid,
        AbstractLocation::from_stack(&Variable::mock("sp", 4), &ByteSize::new(4), &0).unwrap(),
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_strings()
            .get(&expected_r2_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("a".to_string())
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x7c))
            .unwrap(),
        expected_r2_abstract_id
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_strings()
            .get(&expected_stack_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("b".to_string())
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x92))
            .unwrap(),
        expected_stack_abstract_id
    );
}

#[test]
fn test_create_abstract_domain_entries_for_function_arguments_with_unknown_values() {
    let call_tid = Tid::new("func_sprintf_0");
    let r1_reg = Variable::mock("r1", 4);
    let scanf_symbol = ExternSymbol::mock_scanf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(scanf_symbol.clone(), vec![true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();
    let register_arg = Arg::Register{var: r1_reg.clone(), data_type: None};
    let stack_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: None,
    };
    arg_to_value_map.insert(register_arg, None);
    arg_to_value_map.insert(stack_arg, None);

    setup
        .context
        .create_abstract_domain_entries_for_function_arguments(
            &setup.pi_state_before_symbol_call,
            &mut setup.state_before_call,
            &call_tid,
            arg_to_value_map,
        );

    let expected_r1_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r1_reg).unwrap(),
    );

    let expected_stack_abstract_id = AbstractIdentifier::new(
        call_tid,
        AbstractLocation::from_stack(&Variable::mock("sp", 4), &ByteSize::new(4), &0).unwrap(),
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_strings()
            .get(&expected_r1_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("".to_string()).top()
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x74))
            .unwrap(),
        expected_r1_abstract_id
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_strings()
            .get(&expected_stack_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("".to_string()).top()
    );

    assert_eq!(
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x38))
            .unwrap(),
        expected_stack_abstract_id
    );
}

#[test]
fn test_handle_sscanf_calls_unknown_source_unknown_format() {
    let call_tid = Tid::new("func_sprintf_0");
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

    let new_state =
        setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol, &call_tid);

    assert!(new_state.get_strings().is_empty());
    assert!(new_state.get_stack_offset_to_string_map().is_empty());
}

#[test]
fn test_handle_sscanf_calls_known_source_unknown_format() {
    let call_tid = Tid::new("func_sprintf_0");
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

    let new_state =
        setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol, &call_tid);

    assert!(new_state.get_strings().is_empty());
    assert!(new_state.get_stack_offset_to_string_map().is_empty());
}

#[test]
fn test_handle_sscanf_calls_unknown_source_known_format() {
    let call_tid = Tid::new("func_sprintf_0");
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

    let new_state =
        setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol, &call_tid);

    assert!(new_state.get_strings().is_empty());
    assert!(new_state.get_stack_offset_to_string_map().is_empty());
}

#[test]
fn test_handle_sscanf_calls_known_source_known_format() {
    let call_tid = Tid::new("func_sprintf_0");
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();
    let r2_reg = Variable::mock("r2", 4);
    let r3_reg = Variable::mock("r3", 4);

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sscanf_symbol.clone(), vec![true, true])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_r2_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r2_reg).unwrap(),
    );

    let expected_r3_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&r3_reg).unwrap(),
    );

    let expected_stack_1_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_stack(&Variable::mock("sp", 4), &ByteSize::new(4), &0).unwrap(),
    );

    let expected_stack_2_abstract_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_stack(&Variable::mock("sp", 4), &ByteSize::new(4), &4).unwrap(),
    );

    let new_state =
        setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol, &call_tid);

    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_r2_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("str1".to_string())
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_r3_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("str2".to_string())
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_stack_1_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("str3".to_string())
    );
    assert_eq!(
        *new_state
            .get_strings()
            .get(&expected_stack_2_abstract_id)
            .unwrap(),
        CharacterInclusionDomain::from("str4".to_string())
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x7c))
            .unwrap(),
        expected_r2_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x68))
            .unwrap(),
        expected_r3_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x92))
            .unwrap(),
        expected_stack_1_abstract_id
    );
    assert_eq!(
        *new_state
            .get_stack_offset_to_string_map()
            .get(&Bitvector::from_i32(-0x84))
            .unwrap(),
        expected_stack_2_abstract_id
    );
}

#[test]
fn test_map_source_string_parameters_to_return_arguments() {
    let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();
    let r2_arg = Arg::Register{var: Variable::mock("r2", 4), data_type: None};
    let r3_arg = Arg::Register{var: Variable::mock("r3", 4), data_type: None};
    let stack_arg_1 = Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: None,
    };
    let stack_arg_2 = Arg::Stack {
        offset: 4,
        size: ByteSize::new(4),
        data_type: None,
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
fn test_add_new_string_abstract_domain() {
    let call_tid = Tid::new("func_sprintf_0");
    let r2_reg = Variable::mock("r2", 4);
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

    let abstract_id =
        AbstractIdentifier::new(call_tid, AbstractLocation::from_var(&r2_reg).unwrap());

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&Variable::mock("sp", 4)).unwrap(),
    );
    let pointer = PointerDomain::new(
        stack_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        pointer.clone(),
        abstract_id.clone(),
        Some("Hello World".to_string()),
    );

    assert_eq!(
        *state.get_strings().get(&abstract_id).unwrap(),
        CharacterInclusionDomain::from("Hello World".to_string())
    );

    state.set_all_maps_empty();

    Context::<CharacterInclusionDomain>::add_new_string_abstract_domain(
        &mut state,
        &setup.pi_state_before_symbol_call,
        pointer,
        abstract_id.clone(),
        None,
    );

    assert_eq!(
        *state.get_strings().get(&abstract_id).unwrap(),
        CharacterInclusionDomain::from("".to_string()).top()
    );
}

#[test]
fn test_handle_sprintf_and_snprintf_calls_known_format_string() {
    let call_tid = Tid::new("func_sprintf_0");
    let r0_reg = Variable::mock("r0", 4);
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
        &call_tid,
    );

    let expected_abstract_id =
        AbstractIdentifier::new(call_tid, AbstractLocation::from_var(&r0_reg).unwrap());

    let expected_domain = CharacterInclusionDomain::from("cat Hello World %s %s %s".to_string());

    assert!(!new_state.get_strings().is_empty());
    assert_eq!(
        *new_state.get_strings().get(&expected_abstract_id).unwrap(),
        expected_domain
    );
}

#[test]
fn test_handle_sprintf_and_snprintf_calls_unknown_format_string() {
    let call_tid = Tid::new("func_sprintf_0");
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
        &call_tid,
    );

    assert!(new_state.get_strings().is_empty());
}

#[test]
fn test_get_return_destination_from_first_input_parameter() {
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

    let return_arg = Arg::Register{var: Variable::mock("r0", 4), data_type: None};

    let pointer = setup
        .context
        .get_return_destination_from_first_input_parameter(
            &setup.pi_state_before_symbol_call,
            &return_arg,
        );
    let expected_pointer: PointerDomain<IntervalDomain> = PointerDomain::new(
        AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::Register("sp".to_string(), ByteSize::new(4)),
        ),
        IntervalDomain::new(Bitvector::from_i32(-0x54), Bitvector::from_i32(-0x54)),
    );

    assert_eq!(expected_pointer, pointer);
}

#[test]
fn test_get_string_constant_parameter_if_available() {
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

    let var_args = vec![Arg::mock_register("r2", 4), Arg::mock_register("r3", 4)];
    let string_constants = setup
        .context
        .get_string_constant_parameter_if_available(var_args, &setup.pi_state_before_symbol_call);

    assert_eq!(
        vec!["Hello World".to_string(), "%s".to_string()],
        string_constants
    );
}

#[test]
fn test_insert_string_constants_into_format_string() {
    let string = Context::<CharacterInclusionDomain>::insert_string_constants_into_format_string(
        "cat %s".to_string(),
        vec!["Hello World".to_string()],
    );

    assert_eq!("cat Hello World", string);
}

#[test]
fn test_handle_strcat_and_strncat_calls() {}

#[test]
fn test_handle_printf_calls() {}
