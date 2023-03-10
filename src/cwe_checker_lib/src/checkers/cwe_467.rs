//! This module implements a check for CWE-467: Use of sizeof() on a Pointer Type.
//!
//! Functions like malloc and memmove take a size parameter of some data size as
//! input. If accidentially the size of a pointer to the data instead of the size of
//! the data itself gets passed to the function, this can have severe consequences.
//!
//! See <https://cwe.mitre.org/data/definitions/467.html> for a detailed description.
//!
//! ## How the check works
//!
//! We check whether a parameter in a call to a function listed in the symbols for CWE467 (configurable in in config.json)
//! is an immediate value that equals the size of a pointer (e.g. 4 bytes on x86).
//!
//! ## False Positives
//!
//! - The size value might be correct and not a bug.
//!
//! ## False Negatives
//!
//! - If the incorrect size value is generated before the basic block that contains
//! the call, the check will not be able to find it.

use crate::abstract_domain::TryToBitvec;
use crate::analysis::pointer_inference::State;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::{get_callsites, get_symbol_map};
use crate::CweModule;
use std::collections::BTreeSet;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE467",
    version: "0.2",
    run: check_cwe,
};

/// Function symbols read from *config.json*.
/// All parameters of these functions will be checked on whether they are pointer sized.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}

/// Compute the program state at the end of the given basic block
/// assuming nothing is known about the state at the start of the block.
fn compute_block_end_state(project: &Project, block: &Term<Blk>) -> State {
    let stack_register = &project.stack_pointer_register;
    let mut state = State::new(stack_register, block.tid.clone(), BTreeSet::new());

    for def in block.term.defs.iter() {
        match &def.term {
            Def::Store { address, value } => {
                let _ = state.handle_store(address, value, &project.runtime_memory_image);
            }
            Def::Assign { var, value } => {
                state.handle_register_assign(var, value);
            }
            Def::Load { var, address } => {
                let _ = state.handle_load(var, address, &project.runtime_memory_image);
            }
        }
    }
    state
}

/// Check whether a parameter value of the call to `symbol` has value `sizeof(void*)`.
fn check_for_pointer_sized_arg(
    project: &Project,
    block: &Term<Blk>,
    symbol: &ExternSymbol,
) -> bool {
    let pointer_size = project.stack_pointer_register.size;
    let state = compute_block_end_state(project, block);
    for parameter in symbol.parameters.iter() {
        if let Ok(param) = state.eval_parameter_arg(parameter, &project.runtime_memory_image) {
            if let Ok(param_value) = param.try_to_bitvec() {
                if Ok(u64::from(pointer_size)) == param_value.try_to_u64() {
                    return true;
                }
            }
        }
    }
    false
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(jmp: &Term<Jmp>, extern_symbol: &ExternSymbol) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Use of sizeof on a Pointer Type) sizeof on pointer at {} ({}).",
            jmp.tid.address, extern_symbol.name
        ),
    )
    .tids(vec![format!("{}", jmp.tid)])
    .addresses(vec![jmp.tid.address.clone()])
}

/// Execute the CWE check.
///
/// For each call to an extern symbol from the symbol list configured in the configuration file
/// we check whether a parameter has value `sizeof(void*)`,
/// which may indicate an instance of CWE 467.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();

    let symbol_map = get_symbol_map(project, &config.symbols);
    for sub in project.program.term.subs.values() {
        for (block, jmp, symbol) in get_callsites(sub, &symbol_map) {
            if check_for_pointer_sized_arg(project, block, symbol) {
                cwe_warnings.push(generate_cwe_warning(jmp, symbol))
            }
        }
    }
    (Vec::new(), cwe_warnings)
}
