use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;

use super::Context;
use crate::abstract_domain::CharacterInclusionDomain;
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::analysis::string_abstraction::state::State;
use crate::analysis::string_abstraction::tests::mock_project::*;
use crate::intermediate_representation::{Def, ExternSymbol, Project};
use crate::{
    abstract_domain::{AbstractIdentifier, AbstractLocation},
    intermediate_representation::{Arg, ByteSize, Tid, Variable},
    utils::{binary::RuntimeMemoryImage, symbol_utils::get_symbol_map},
};

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
    let arg = Arg::Register(rdi_reg.clone());

    let project = mock_project_with_intraprocedural_control_flow(vec![], "");
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let context: Context<CharacterInclusionDomain> = Context::mock(
        &project,
        mock_string_symbol_map(&project),
        mock_format_index_map(),
        &pi_results,
        &mem_image,
    );

    let expected_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_var(&rdi_reg).unwrap(),
    );

    assert_eq!(
        expected_id,
        context.get_abstract_id_for_function_parameter(&arg, &call_tid)
    );
}

#[test]
fn test_get_abstract_id_for_function_parameter_from_stack() {
    let call_tid = Tid::new("call");
    let sp_reg = Variable::mock("sp", 4);
    let arg = Arg::Stack {
        offset: 8,
        size: ByteSize::new(8),
    };

    let project = mock_project_with_intraprocedural_control_flow(vec![], "");
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let context: Context<CharacterInclusionDomain> = Context::mock(
        &project,
        mock_string_symbol_map(&project),
        mock_format_index_map(),
        &pi_results,
        &mem_image,
    );

    let expected_id = AbstractIdentifier::new(
        call_tid.clone(),
        AbstractLocation::from_stack(&sp_reg, &ByteSize::new(8), &8).unwrap(),
    );

    assert_eq!(
        expected_id,
        context.get_abstract_id_for_function_parameter(&arg, &call_tid)
    );
}

#[test]
fn test_handle_string_symbol_calls() {}

#[test]
fn test_handle_scanf_and_sscanf_calls() {}

#[test]
fn test_add_new_string_abstract_domain() {}

#[test]
fn test_handle_sprintf_and_snprintf_calls_known_format_string() {
    let call_tid = Tid::new("call");
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project =
        mock_project_with_intraprocedural_control_flow(vec![(sprintf_symbol, vec![true])], "func");
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let state: State<CharacterInclusionDomain> =
        State::mock_with_default_pi_state(project.program.term.subs.get(0).unwrap().clone());

    let context: Context<CharacterInclusionDomain> = Context::mock(
        &project,
        mock_string_symbol_map(&project),
        mock_format_index_map(),
        &pi_results,
        &mem_image,
    );
}

#[test]
fn test_handle_sprintf_and_snprintf_calls_unknown_format_string() {
    let call_tid = Tid::new("func_sprintf_0");
    let r0_reg = Variable::mock("r0", ByteSize::new(4));
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![false])],
        "func",
    );
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&project, &mem_image, &graph);
    pi_results.compute();

    let mut pi_state = pi_results
        .get_node_value(NodeIndex::new(0))
        .unwrap()
        .unwrap_value()
        .clone();

    let pi_context = pi_results.get_context();
    for def in project.program.term.subs.get(0).unwrap().term.blocks.get(0).unwrap().term.defs.iter() {
        pi_state = pi_context.update_def(&pi_state, def).unwrap();
    }

    let state: State<CharacterInclusionDomain> = State::mock_with_given_pi_state(
        project.program.term.subs.get(0).unwrap().clone(),
        pi_state.clone(),
    );

    let context: Context<CharacterInclusionDomain> = Context::mock(
        &project,
        mock_string_symbol_map(&project),
        mock_format_index_map(),
        &pi_results,
        &mem_image,
    );

    let new_state = context.handle_sprintf_and_snprintf_calls(&state, &sprintf_symbol, &call_tid);

    let expected_abstract_id =
        AbstractIdentifier::new(call_tid, AbstractLocation::from_var(&r0_reg).unwrap());

    if let Some(domain) = new_state.get_strings().get(&expected_abstract_id) {
        match domain {
            CharacterInclusionDomain::Value((must, can)) => {
                println!("MUST: {:?}", must);
                println!("CAN: {:?}", can);
            }
            CharacterInclusionDomain::Top => println!("To the Top!"),
        }
    } else {
        println!("No Abstract ID found or something else went wrong");
    }
}

#[test]
fn test_get_return_destination_from_first_input_parameter() {}

#[test]
fn test_get_string_constant_parameter_if_available() {}

#[test]
fn test_insert_string_constants_into_format_string() {}

#[test]
fn test_handle_strcat_and_strncat_calls() {}

#[test]
fn test_handle_printf_calls() {}
