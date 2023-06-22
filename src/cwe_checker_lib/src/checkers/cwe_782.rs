/*!
This module implements a check for CWE-782: Exposed IOCTL with Insufficient Access Control.

See <https://cwe.mitre.org/data/definitions/782.html> for a detailed description.

How the check works:

* Calls to ioctl() get flagged as CWE hits.

False Positives:

* We cannot check whether the call contains sufficient access control.

False Negatives:

* There are other ways to expose I/O control without access control.
*/
use crate::prelude::*;
use std::collections::HashMap;

use crate::{
    intermediate_representation::{Program, Sub, Term, Tid},
    utils::{
        log::{CweWarning, LogMessage},
        symbol_utils::{find_symbol, get_calls_to_symbols},
    },
};

const VERSION: &str = "0.1";

/// The module name and version
pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "CWE782",
    version: VERSION,
    run: check_cwe,
};

/// check whether the ioctl symbol is called by any subroutine. If so, generate the cwe warning.
pub fn handle_sub(sub: &Term<Sub>, symbol: &HashMap<&Tid, &str>) -> Vec<CweWarning> {
    let calls: Vec<(&str, &Tid, &str)> = get_calls_to_symbols(sub, symbol);
    if !calls.is_empty() {
        return generate_cwe_warning(&calls);
    }
    vec![]
}

/// generate the cwe warning for CWE 782
pub fn generate_cwe_warning(calls: &[(&str, &Tid, &str)]) -> Vec<CweWarning> {
    let mut cwe_warnings: Vec<CweWarning> = Vec::new();
    for (sub_name, jmp_tid, _) in calls.iter() {
        let address: &String = &jmp_tid.address;
        let description = format!(
            "(Exposed IOCTL with Insufficient Access Control) Program uses ioctl at {sub_name} ({address}). Be sure to double check the program and the corresponding driver.");
        let cwe_warning = CweWarning::new(
            String::from(CWE_MODULE.name),
            String::from(CWE_MODULE.version),
            description,
        )
        .addresses(vec![address.clone()])
        .tids(vec![format!("{jmp_tid}")])
        .symbols(vec![String::from(*sub_name)]);

        cwe_warnings.push(cwe_warning);
    }
    cwe_warnings
}

/// Iterate through all calls of the program and flag calls to `ioctl()` as CWE warnings.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    _cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let prog: &Term<Program> = &project.program;
    let mut warnings: Vec<CweWarning> = Vec::new();
    if let Some((tid, name)) = find_symbol(prog, "ioctl") {
        let symbol: &HashMap<&Tid, &str> = &[(tid, name)].iter().cloned().collect();
        prog.term
            .subs
            .values()
            .for_each(|sub| warnings.append(&mut handle_sub(sub, symbol)));
    }

    (vec![], warnings)
}
