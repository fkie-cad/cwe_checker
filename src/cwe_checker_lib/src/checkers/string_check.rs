use petgraph::visit::EdgeRef;

use crate::CweModule;

use crate::abstract_domain::BricksDomain;
use crate::abstract_domain::CharacterInclusionDomain;
use crate::analysis::graph::Edge;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::analysis::string_abstraction::context::Context;
use crate::analysis::string_abstraction::state::State;
use crate::analysis::string_abstraction::Config as StringAbstractConfig;
use crate::analysis::string_abstraction::StringAbstraction;
use crate::intermediate_representation::Arg;
use crate::intermediate_representation::ExternSymbol;
use crate::intermediate_representation::Jmp;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;

use std::fmt::Debug;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "StringCheck",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Config {
    /// The names of the system call symbols
    system_symbols: Vec<String>,
    /// Contains the config parameters for the abstract string analysis.
    abstract_strings: StringAbstractConfig,
}

/// IMPORTANT NOTE!: To switch between the analysis using the CI and BR domain,
/// change the generic parameter to the StringAbstraction Object accordingly.
/// Further down in the function, switch the function call between:
/// "check_system_call_parameter_with_ci_domain" and
/// "check_system_call_parameter_with_br_domain"
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut string_abstraction: StringAbstraction<CharacterInclusionDomain> =
        StringAbstraction::new(
            analysis_results.project,
            analysis_results.runtime_memory_image,
            analysis_results.control_flow_graph,
            analysis_results.pointer_inference.unwrap(),
            config.abstract_strings,
        );
    string_abstraction.compute();

    let external_symbols = &string_abstraction
        .get_context()
        .project
        .program
        .term
        .extern_symbols;
    let system_symbol_index = external_symbols
        .iter()
        .position(|symbol| symbol.name == "system")
        .unwrap();
    let string_graph = string_abstraction.get_graph();

    if let Some(system_symbol) = external_symbols.get(system_symbol_index) {
        for edge in string_graph.edge_references() {
            if let Edge::ExternCallStub(jmp) = edge.weight() {
                if let Jmp::Call { target, .. } = &jmp.term {
                    if system_symbol.tid == *target {
                        if let Some(source_node) = string_abstraction.get_node_value(edge.source())
                        {
                            if let Some(pi_node) = analysis_results
                                .pointer_inference
                                .unwrap()
                                .get_node_value(edge.source())
                            {
                                let pi_state = pi_node.unwrap_value();
                                let source_state = source_node.unwrap_value();
                                check_system_call_parameter_with_ci_domain(
                                    source_state,
                                    pi_state,
                                    system_symbol,
                                    &jmp.tid,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    (vec![], vec![])
}

/// Checks the system call parameter given by the Bricks Domain.
pub fn check_system_call_parameter_with_br_domain(
    source_state: &State<BricksDomain>,
    pi_state: &PointerInferenceState,
    system_symbol: &ExternSymbol,
    jmp_tid: &Tid,
) {
    if let Some(Arg::Register { var, .. }) = system_symbol.parameters.get(0) {
        if let Some(value) = source_state.get_variable_to_pointer_map().get(var) {
            let contains_string_constant = value.get_absolute_value().is_some();
            let contains_relative_string_pointer = !value.get_relative_values().is_empty();
            if contains_string_constant && !contains_relative_string_pointer {
                println!(
                    "Input of system call at {} constant. Not vulnerable.",
                    jmp_tid.address
                );
            } else if contains_relative_string_pointer {
                check_if_string_domain_indicates_vulnerability_with_br_domain(
                    Context::<BricksDomain>::merge_domains_from_multiple_pointer_targets(
                        source_state,
                        pi_state,
                        value.get_relative_values(),
                    ),
                    jmp_tid,
                );
            } else {
                println!(
                    "Input of system call at {} unknown. Possibly vulnerable.",
                    jmp_tid.address
                )
            }
        } else {
            println!(
                "No Parameter tracked For System Call at {}",
                jmp_tid.address
            );
        }
    }
}

/// Checks if the CharacterInclusion Domain indicates a vulnerability at the system call.
pub fn check_if_string_domain_indicates_vulnerability_with_br_domain(
    input_domain: BricksDomain,
    jmp_tid: &Tid,
) {
    match &input_domain {
        BricksDomain::Top => {
            println!(
                "Input of system call at {} unknown. Possibly vulnerable.\n Domain: {:?}",
                jmp_tid.address, input_domain
            );
        }
        BricksDomain::Value(bricks) => {
            let fully_known = bricks
                .iter()
                .any(|brick| matches!(brick, crate::abstract_domain::BrickDomain::Top));
            if !fully_known {
                println!(
                    "Input of system call at {} without dangerous chars. Not vulnerable.\n Domain: {:?}",
                    jmp_tid.address, input_domain
                );
            } else {
                println!(
                    "Input of system call at {} partially unknown. Possibly vulnerable.\n Domain: {:?}",
                    jmp_tid.address, input_domain
                );
            }
        }
    }
}

/// Checks the system call parameter given by the CharacterInclusion Domain.
pub fn check_system_call_parameter_with_ci_domain(
    source_state: &State<CharacterInclusionDomain>,
    pi_state: &PointerInferenceState,
    system_symbol: &ExternSymbol,
    jmp_tid: &Tid,
) {
    if let Some(Arg::Register { var, .. }) = system_symbol.parameters.get(0) {
        if let Some(value) = source_state.get_variable_to_pointer_map().get(var) {
            let contains_string_constant = value.get_absolute_value().is_some();
            let contains_relative_string_pointer = !value.get_relative_values().is_empty();
            if contains_string_constant && !contains_relative_string_pointer {
                println!(
                    "Input of system call at {} constant. Not vulnerable.",
                    jmp_tid.address
                );
            } else if contains_relative_string_pointer {
                check_if_string_domain_indicates_vulnerability_with_ci_domain(
                    Context::<CharacterInclusionDomain>::merge_domains_from_multiple_pointer_targets(
                        source_state,
                        pi_state,
                        value.get_relative_values(),
                    ),
                    jmp_tid,
                );
            } else {
                println!(
                    "Input of system call at {} unknown. Possibly vulnerable.",
                    jmp_tid.address
                )
            }
        } else {
            println!(
                "No Parameter tracked For System Call at {}",
                jmp_tid.address
            );
        }
    }
}

/// Checks if the Bricks Domain indicates a vulnerability at the system call.
pub fn check_if_string_domain_indicates_vulnerability_with_ci_domain(
    input_domain: CharacterInclusionDomain,
    jmp_tid: &Tid,
) {
    match &input_domain {
        CharacterInclusionDomain::Top => {
            println!(
                "Input of system call at {} unknown. Possibly vulnerable.\n Domain: {:?}",
                jmp_tid.address, input_domain
            );
        }
        CharacterInclusionDomain::Value((certain, possible)) => match possible {
            crate::abstract_domain::CharacterSet::Top => match certain {
                crate::abstract_domain::CharacterSet::Value(value) => {
                    if value.is_empty() {
                        println!(
                            "Input of system call at {} unknown. Possibly vulnerable.",
                            jmp_tid.address
                        )
                    } else {
                        println!(
                                "Input of system call at {} partially unknown. Possibly vulnerable.\n Domain: {:?}",
                                jmp_tid.address, input_domain
                            );
                    }
                }
                _ => panic!("Invalid Top value for certain character set."),
            },
            crate::abstract_domain::CharacterSet::Value(_) => {
                println!(
                    "Input of system call at {} without dangerous chars. Not vulnerable.\n Domain: {:?}",
                    jmp_tid.address, input_domain
                );
            }
        },
    }
}
