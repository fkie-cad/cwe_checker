//! This module implements a check for CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection').
//!
//! The software constructs all or part of an OS command using externally-influenced input from an upstream component,
//! but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command
//! when it is sent to a downstream component.
//!
//! See <https://cwe.mitre.org/data/definitions/78.html> for a detailed description.
//!
//! ## How the check works
//!
//! The check depends entirely on the string abstraction analysis that is run beforehand.
//! The string abstraction uses a forward fixpoint analysis to determine potential strings at all
//! nodes in the CFG. More detailed information about the string abstraction can be found in the
//! corresponding files.
//!
//! The BricksDomain, a string abstract domain defining a string as a sequence of substring sets (bricks)
//! is used for this check. As it considers the order of characters, it can be further used for a manual
//! post analysis of the commands given to system calls.
//!
//! ### Symbols configurable in config.json
//!
//! The system calls considered in this check can be configured in the config.json.
//!
//! ## False Positives
//!
//! - The input comes from the user but proper sanitization was not detected by the analysis even though it exists.
//! - The input comes from the user but the format string's input format could not be distinguished as non-string input.
//!
//! ## False Negatives
//!
//! - Missing substrings due to lost track of pointer targets
//! - Non tracked function parameters cause incomplete strings that could miss possible dangerous inputs

use petgraph::visit::EdgeRef;

use crate::CweModule;

use crate::abstract_domain::BricksDomain;
use crate::abstract_domain::TryToBitvec;
use crate::analysis::graph::Edge;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::analysis::string_abstraction::context::Context;
use crate::analysis::string_abstraction::state::State;
use crate::intermediate_representation::Arg;
use crate::intermediate_representation::Expression;
use crate::intermediate_representation::ExternSymbol;
use crate::intermediate_representation::Jmp;
use crate::intermediate_representation::RuntimeMemoryImage;
use crate::intermediate_representation::Sub;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;

use std::collections::BTreeMap;
use std::fmt::Debug;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE78",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Config {
    /// The names of the system call symbols
    system_symbols: Vec<String>,
}

/// This check checks the string parameter at system calls given by the string abstraction analysis
/// to find potential OS Command Injection vulnerabilities.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let (cwe_sender, cwe_receiver): (
        crossbeam_channel::Sender<CweWarning>,
        crossbeam_channel::Receiver<CweWarning>,
    ) = crossbeam_channel::unbounded();
    let (log_sender, log_receiver): (
        crossbeam_channel::Sender<LogMessage>,
        crossbeam_channel::Receiver<LogMessage>,
    ) = crossbeam_channel::unbounded();
    let string_abstraction = analysis_results.string_abstraction.unwrap();

    let system_symbol: Option<(Tid, ExternSymbol)> = string_abstraction
        .get_context()
        .project
        .program
        .term
        .extern_symbols
        .clone()
        .into_iter()
        .find(|(_, symbol)| config.system_symbols.contains(&symbol.name));
    let string_graph = string_abstraction.get_graph();

    if let Some((_, system)) = system_symbol {
        for edge in string_graph.edge_references() {
            if let Edge::ExternCallStub(jmp) = edge.weight() {
                if let Jmp::Call { target, .. } = &jmp.term {
                    if system.tid == *target {
                        if let Some(source_node) = string_abstraction.get_node_value(edge.source())
                        {
                            if let Some(pi_node) = analysis_results
                                .pointer_inference
                                .unwrap()
                                .get_node_value(edge.source())
                            {
                                let pi_state = pi_node.unwrap_value();
                                let source_state = source_node.unwrap_value();
                                check_system_call_parameter(
                                    source_state,
                                    pi_state,
                                    &system,
                                    &jmp.tid,
                                    &cwe_sender,
                                    &log_sender,
                                    &string_abstraction
                                        .get_context()
                                        .project
                                        .runtime_memory_image,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cwe_warnings = BTreeMap::new();
    for cwe in cwe_receiver.try_iter() {
        match &cwe.addresses[..] {
            [taint_source_address, ..] => cwe_warnings.insert(taint_source_address.clone(), cwe),
            _ => panic!(),
        };
    }

    let cwe_warnings = cwe_warnings.into_values().collect();
    let log_messages = log_receiver.try_iter().collect();

    (log_messages, cwe_warnings)
}

/// Checks the system call parameter given by the Bricks Domain.
pub fn check_system_call_parameter(
    source_state: &State<BricksDomain>,
    pi_state: &PointerInferenceState,
    system_symbol: &ExternSymbol,
    jmp_tid: &Tid,
    cwe_collector: &crossbeam_channel::Sender<CweWarning>,
    log_collector: &crossbeam_channel::Sender<LogMessage>,
    runtime_memory_image: &RuntimeMemoryImage,
) {
    let sub = source_state.get_current_sub().unwrap();
    if let Some(Arg::Register {
        expr: Expression::Var(var),
        ..
    }) = system_symbol.parameters.get(0)
    {
        if let Some(value) = source_state.get_variable_to_pointer_map().get(var) {
            let contains_string_constant = value.get_absolute_value().is_some();
            let contains_relative_string_pointer = !value.get_relative_values().is_empty();
            if contains_relative_string_pointer {
                let mut parameter_domain =
                    Context::<BricksDomain>::merge_domains_from_multiple_pointer_targets(
                        source_state,
                        pi_state,
                        value.get_relative_values(),
                    );
                if contains_string_constant {
                    if let Ok(global_string) = runtime_memory_image
                        .read_string_until_null_terminator(
                            &value.get_absolute_value().unwrap().try_to_bitvec().unwrap(),
                        )
                    {
                        parameter_domain.widen(&BricksDomain::from(global_string.to_string()));
                    } else {
                        parameter_domain = BricksDomain::Top;
                    }
                }
                check_if_string_domain_indicates_vulnerability(
                    parameter_domain,
                    jmp_tid,
                    sub,
                    system_symbol,
                    cwe_collector,
                );
            } else if !contains_string_constant && !contains_relative_string_pointer {
                let _ = cwe_collector.send(generate_cwe_warning(
                    &sub.term.name,
                    jmp_tid,
                    &system_symbol.name,
                ));
            }
        } else {
            let _ = log_collector.send(LogMessage::new_debug(format!(
                "No Parameter tracked for system call at {}",
                jmp_tid.address
            )));
        }
    }
}

/// Checks if the Bricks Domain indicates a vulnerability at the system call.
pub fn check_if_string_domain_indicates_vulnerability(
    input_domain: BricksDomain,
    jmp_tid: &Tid,
    sub: &Term<Sub>,
    system_symbol: &ExternSymbol,
    cwe_collector: &crossbeam_channel::Sender<CweWarning>,
) {
    match &input_domain {
        BricksDomain::Top => {
            let _ = cwe_collector.send(generate_cwe_warning(
                &sub.term.name,
                jmp_tid,
                &system_symbol.name,
            ));
        }
        BricksDomain::Value(bricks) => {
            let partially_known = bricks
                .iter()
                .any(|brick| matches!(brick, crate::abstract_domain::BrickDomain::Top));
            if partially_known {
                let _ = cwe_collector.send(generate_cwe_warning(
                    &sub.term.name,
                    jmp_tid,
                    &system_symbol.name,
                ));
            }
        }
    }
}

/// Generates the CWE Warning for the CWE 78 check
pub fn generate_cwe_warning(sub_name: &str, jmp_tid: &Tid, symbol_name: &str) -> CweWarning {
    let description: String = format!(
        "(OS Command Injection) Input for call to {} may not be properly sanitized in function {} ({})",
        symbol_name, sub_name, jmp_tid.address,
    );
    CweWarning::new(
        String::from(CWE_MODULE.name),
        String::from(CWE_MODULE.version),
        description,
    )
    .addresses(vec![jmp_tid.address.clone()])
    .tids(vec![format!("{}", jmp_tid)])
    .symbols(vec![String::from(sub_name)])
    .other(vec![vec![
        String::from("OS Command Injection"),
        symbol_name.to_string(),
    ]])
}
