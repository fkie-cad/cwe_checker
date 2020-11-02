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
//! a certain value, currently set to 1000 and greater than a reasonable value for umask, currently set to 100.
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

use crate::abstract_domain::{BitvectorDomain, DataDomain};
use crate::analysis::pointer_inference::State;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::CweModule;

pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE560",
    version: "0.2",
    run: check_cwe,
};

pub static UPPER_BOUND_CORRECT_UMASK_ARG_VALUE: u64 = 100;
pub static UPPER_BOUND_CORRECT_CHMOD_ARG_VALUE: u64 = 1000;

/// Compute the parameter value of umask out of the basic block right before the umask call.
///
/// The function uses the same `State` struct as the pointer inference analysis for the computation.
fn get_umask_permission_arg(
    block: &Term<Blk>,
    umask_symbol: &ExternSymbol,
    project: &Project,
) -> Result<u64, Error> {
    let stack_register = &project.stack_pointer_register;
    let mut state = State::new(stack_register, block.tid.clone());

    for def in block.term.defs.iter() {
        match &def.term {
            Def::Store { address, value } => {
                let _ = state.handle_store(address, value);
            }
            Def::Assign { var, value } => {
                let _ = state.handle_register_assign(var, value);
            }
            Def::Load { var, address } => {
                let _ = state.handle_load(var, address);
            }
        }
    }

    let parameter = umask_symbol.get_unique_parameter()?;
    let param_value = state.eval_parameter_arg(parameter, &project.stack_pointer_register)?;
    if let DataDomain::Value(BitvectorDomain::Value(umask_arg)) = param_value {
        Ok(umask_arg.try_to_u64()?)
    } else {
        Err(anyhow!("Parameter value unknown"))
    }
}

/// Determine whether the given jump is a call to umask.
fn is_call_to_umask(jmp: &Term<Jmp>, umask_tid: &Tid) -> bool {
    matches!(&jmp.term, Jmp::Call { target, .. } if target == umask_tid)
}

/// Is the given argument value considered to be a chmod-style argument?
fn is_chmod_style_arg(arg: u64) -> bool {
    arg > UPPER_BOUND_CORRECT_UMASK_ARG_VALUE && arg <= UPPER_BOUND_CORRECT_CHMOD_ARG_VALUE
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(sub: &Term<Sub>, jmp: &Term<Jmp>, permission_const: u64) -> CweWarning {
    CweWarning::new(CWE_MODULE.name, CWE_MODULE.version,
        format!("(Use of umask() with chmod-style Argument) Function {} calls umask with argument {:#o}", sub.term.name, permission_const))
        .tids(vec![format!("{}", jmp.tid)])
        .addresses(vec![jmp.tid.address.clone()])
        .other(vec![vec![
            "umask_arg".to_string(),
            format!("{:#o}", permission_const),
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
    project: &Project,
    _cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let mut cwes = Vec::new();
    let mut log_messages = Vec::new();
    if let Some(umask_symbol) = project
        .program
        .term
        .extern_symbols
        .iter()
        .find(|symbol| symbol.name == "umask")
    {
        let umask_tid = &umask_symbol.tid;
        for sub in project.program.term.subs.iter() {
            for block in sub.term.blocks.iter() {
                if let Some(jmp) = block
                    .term
                    .jmps
                    .iter()
                    .find(|jmp| is_call_to_umask(jmp, umask_tid))
                {
                    match get_umask_permission_arg(block, umask_symbol, project) {
                        Ok(permission_const) => {
                            if is_chmod_style_arg(permission_const) {
                                cwes.push(generate_cwe_warning(sub, jmp, permission_const));
                            }
                        }
                        Err(err) => {
                            let log = LogMessage::new_info(format!(
                                "Could not determine umask argument: {}",
                                err
                            ))
                            .location(jmp.tid.clone())
                            .source(CWE_MODULE.name);
                            log_messages.push(log);
                        }
                    }
                }
            }
        }
    }

    (log_messages, cwes)
}
