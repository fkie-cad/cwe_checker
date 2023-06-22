//! This module implements a check for CWE-426: Untrusted Search Path.
//!
//! Basically, the program searches for critical resources on an untrusted search
//! path that can be adjusted by an adversary. For example, see Nebula Level 1
//! (<https://exploit-exercises.com/nebula/level01/>).
//!
//! According to the manual page of system() the following problems can arise:
//! "Do not use system() from a program with set-user-ID or set-group-ID privileges,
//! because strange values for some environment variables might be used to subvert
//! system integrity.  Use the exec(3) family of functions instead, but not execlp(3)
//! or execvp(3).  system() will not, in fact, work properly from programs with set-user-ID
//! or set-group-ID privileges on systems on which /bin/sh is bash version 2, since bash 2
//! drops privileges on startup. (Debian uses a modified bash which does not do this when invoked as sh.)"
//!
//! See <https://cwe.mitre.org/data/definitions/426.html> for a detailed description.
//!
//! ## How the check works
//!
//! We check whether a function that calls a privilege-changing function (configurable
//! in config.json) also calls system().
//!
//! ## False Positives
//!
//! - If the call to system() happens before the privilege-changing function, the call
//! may not be used for privilege escalation
//!
//! ## False Negatives
//!
//! - If the calls to the privilege-changing function and system() happen in different
//! functions, the calls will not be flagged as a CWE-hit.
//! - This check only finds potential privilege escalation bugs, but other types of
//! bugs can also be triggered by untrusted search paths.

use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::{find_symbol, get_calls_to_symbols};
use crate::CweModule;
use std::collections::HashMap;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE426",
    version: "0.1",
    run: check_cwe,
};

/// Function symbols read from *config.json*.
/// The symbols are functions that change or drop privileges.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(sub: &Term<Sub>) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Untrusted Search Path) sub {} at {} may be vulnerable to PATH manipulation.",
            sub.term.name, sub.tid.address
        ),
    )
    .tids(vec![format!("{}", sub.tid)])
    .addresses(vec![sub.tid.address.clone()])
    .symbols(vec![sub.term.name.clone()])
}

/// Run the CWE check.
/// We check whether a function calls both `system(..)` and a privilege changing function.
/// For each such function a CWE warning is generated.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();
    let mut privilege_changing_symbols = HashMap::new();
    for symbol in config.symbols.iter() {
        if let Some((tid, name)) = find_symbol(&project.program, symbol) {
            privilege_changing_symbols.insert(tid, name);
        }
    }
    let mut system_symbol = HashMap::new();
    if let Some((tid, name)) = find_symbol(&project.program, "system") {
        system_symbol.insert(tid, name);
    }
    if !system_symbol.is_empty() && !privilege_changing_symbols.is_empty() {
        for sub in project.program.term.subs.values() {
            if !get_calls_to_symbols(sub, &system_symbol).is_empty()
                && !get_calls_to_symbols(sub, &privilege_changing_symbols).is_empty()
            {
                cwe_warnings.push(generate_cwe_warning(sub));
            }
        }
    }
    (Vec::new(), cwe_warnings)
}
