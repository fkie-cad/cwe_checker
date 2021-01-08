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
//! Using dataflow analysis we search for an executation path from a system call parameter (string) to an user input
//! to identify possible command injections.
//!
//! ### Symbols configurable in config.json
//!
//! The symbols are the functions which
//!   1. take user input (e.g. scanf)
//!   2. make system calls (e.g. system)
//!   3. manipulate strings (e.g. sprintf, strcat, memcpy, etc.)
//!   4. check strings for characters (e.g. regexp)
//!
//! ## False Positives
//!
//! - The input comes from the user but proper sanitization was not detected by the analysis even though it exists.
//! - The input comes from the user but the format string's input format could not be distinguised as non-string.
//!
//! ## False Negatives
//!
//! -

use crate::{
    analysis::backward_interprocedural_fixpoint::Context as _,
    prelude::*,
    utils::log::{CweWarning, LogMessage},
    AnalysisResults, CweModule,
};

mod state;
use state::*;

mod context;
use context::*;

mod taint;
use taint::*;

pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE78",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// The names of the user input symbols
    input_symbols: Vec<String>,
    /// The names of the string manipulation symbols
    string_symbols: Vec<String>,
    /// The names of the system call symbols
    system_symbols: Vec<String>,
    /// The names of the symbols for sanitizing strings
    sanitize_symbols: Vec<String>,
}

pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pointer_inference_results = analysis_results.pointer_inference.unwrap();

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let symbol_map = crate::utils::symbol_utils::get_symbol_map(project, &config.symbols[..]);
    let general_context = Context::new(project, &pointer_inference_results, cwe_sender);

    (Vec::new(), Vec::new())
}
