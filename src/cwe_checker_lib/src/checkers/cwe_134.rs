//! This module implements a check for CWE-134: Use of Externally-Controlled Format String.
//!
//! The software uses a function that accepts a format string as an argument,
//! but the format string originates from an external source.
//!
//! See <https://cwe.mitre.org/data/definitions/134.html> for a detailed description.
//!
//! ## How the check works
//!
//! Using forward dataflow analysis we search for external symbols that take a format string as an input parameter.
//! (e.g. sprintf). Then we check the content of the format string parameter and if it is not part of the fixed read only
//! memory of the binary, a CWE warning is generated.
//!
//! ### Symbols configurable in config.json
//!
//! - symbols that take a format string parameter.
//!
//! ## False Positives
//!
//! - The input was externally provided on purpose and originates from a trusted source.
//!
//! ## False Negatives
//!
//! - A pointer targeting read only memory could be lost.

use std::collections::HashMap;

use crate::analysis::graph::Edge;
use crate::intermediate_representation::ExternSymbol;
use crate::intermediate_representation::Jmp;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::CweModule;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE134",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Config {
    /// The names of the system call symbols
    format_string_symbols: Vec<String>,
    format_string_index: HashMap<String, usize>,
}

/// This check searches for external symbols that take a format string as an input parameter.
/// I then checks whether the parameter points to read only memory.
/// If no, a CWE warning is generated.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let format_string_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.format_string_symbols[..]);
    let format_string_index = config.format_string_index.clone();

    let pointer_inference_results = analysis_results.pointer_inference.unwrap();
    let mut cwe_warnings = Vec::new();

    for edge in pointer_inference_results.get_graph().edge_references() {
        if let Edge::ExternCallStub(jmp) = edge.weight() {
            if let Jmp::Call { target, .. } = &jmp.term {
                if let Some(symbol) = format_string_symbols.get(target) {}
            }
        }
    }

    (Vec::new(), cwe_warnings)
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(callsite: &Tid, called_symbol: &ExternSymbol) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Externally Controlled Format String) Potential externally controlled format string for call to {} at {}",
            called_symbol.name, callsite.address
        ))
        .tids(vec![format!("{}", callsite)])
        .addresses(vec![callsite.address.clone()])
        .symbols(vec![called_symbol.name.clone()])
}
