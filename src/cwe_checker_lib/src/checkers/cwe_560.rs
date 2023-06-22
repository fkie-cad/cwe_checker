//! This module implements a check for CWE-560: Use of umask() with chmod-style Argument.
//!
//! The program uses the system call umask(2) with arguments for chmod(2). For instance,
//! instead of a reasonable value like 0022 a value like 0666 is passed. This may result in wrong
//! read and/or write access to files and directories, which could be utilized to bypass
//! protection mechanisms.
//!
//! See <https://cwe.mitre.org/data/definitions/560.html> for a detailed description.
//!
//! ## How the check works
//!
//! This check looks for umask calls and checks if they have a reasonable value, i.e. smaller than
//! a certain value, currently set to 0o777 and greater than a reasonable value for umask, currently set to 0o177.
//!
//! ## False Positives
//!
//! - A value deemed unreasonable by the check could theoretically be intended by the programmer.
//! But these cases should be very rare in real programs, so be sure to double check them!
//!
//! ## False Negatives
//!
//! - If the input to umask is not defined in the basic block before the call, the check will not see it.
//! However, a log message will be generated whenever the check is unable to determine the parameter value of umask.

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
    name: "CWE560",
    version: "0.2",
    run: check_cwe,
};

/// An upper bound for the value of a presumably correct umask argument.
pub static UPPER_BOUND_CORRECT_UMASK_ARG_VALUE: u64 = 0o177;
/// An upper bound for the value of a chmod-style argument.
pub static UPPER_BOUND_CORRECT_CHMOD_ARG_VALUE: u64 = 0o777;

/// Compute the parameter value of umask out of the basic block right before the umask call.
///
/// The function uses the same `State` struct as the pointer inference analysis for the computation.
fn get_umask_permission_arg(
    block: &Term<Blk>,
    umask_symbol: &ExternSymbol,
    project: &Project,
) -> Result<u64, Error> {
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

    let parameter = umask_symbol.get_unique_parameter()?;
    let param_value = state.eval_parameter_arg(parameter, &project.runtime_memory_image)?;
    if let Ok(umask_arg) = param_value.try_to_bitvec() {
        Ok(umask_arg.try_to_u64()?)
    } else {
        Err(anyhow!("Parameter value unknown"))
    }
}

/// Is the given argument value considered to be a chmod-style argument?
///
/// Note that `0o777` is not considered a chmod-style argument as it also denotes a usually correct umask argument.
fn is_chmod_style_arg(arg: u64) -> bool {
    arg > UPPER_BOUND_CORRECT_UMASK_ARG_VALUE && arg != UPPER_BOUND_CORRECT_CHMOD_ARG_VALUE
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(sub: &Term<Sub>, jmp: &Term<Jmp>, permission_const: u64) -> CweWarning {
    CweWarning::new(CWE_MODULE.name, CWE_MODULE.version,
        format!("(Use of umask() with chmod-style Argument) Function {} calls umask with argument {:#o}", sub.term.name, permission_const))
        .tids(vec![format!("{}", jmp.tid)])
        .addresses(vec![jmp.tid.address.clone()])
        .other(vec![vec![
            "umask_arg".to_string(),
            format!("{permission_const:#o}"),
        ]])
}

/// Execute the CWE check.
///
/// For each call to umask we check whether the parameter value is a chmod-style parameter.
/// If yes, generate a CWE warning.
/// If the parameter value cannot be determined, generate a log message.
///
/// Only the basic block right before the umask call is evaluated when trying to determine the parameter value of umask.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    _cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let mut cwes = Vec::new();
    let mut log_messages = Vec::new();
    let umask_symbol_map = get_symbol_map(project, &["umask".to_string()]);
    if !umask_symbol_map.is_empty() {
        for sub in project.program.term.subs.values() {
            for (block, jmp, umask_symbol) in get_callsites(sub, &umask_symbol_map) {
                match get_umask_permission_arg(block, umask_symbol, project) {
                    Ok(permission_const) => {
                        if is_chmod_style_arg(permission_const) {
                            cwes.push(generate_cwe_warning(sub, jmp, permission_const));
                        }
                    }
                    Err(err) => {
                        let log = LogMessage::new_info(format!(
                            "Could not determine umask argument: {err}"
                        ))
                        .location(jmp.tid.clone())
                        .source(CWE_MODULE.name);
                        log_messages.push(log);
                    }
                }
            }
        }
    }

    (log_messages, cwes)
}
