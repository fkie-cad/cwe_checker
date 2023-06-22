//! This module implements a check for CWE-789: Memory Allocation with Excessive Size Value.
//!
//! Stack memory allocation and function calls like malloc are covered in this module.
//! Excessive allocation of memory might destabilize programs on machines with limited resources.
//!
//! See <https://cwe.mitre.org/data/definitions/789.html> for a detailed description.
//!
//! ## How the check works
//!
//! Every instruction is checked if it assigns a new value to the stack pointer. If
//! this is the case, the value range of the assignment is checked and if it
//! exceeds the defined `stack_threshold` defined in config.json, a warning is generated.
//! For calls like malloc, the provided argument is checked, if its value exceeds
//! the defined `heap_threshold`. The covered function calls are defined in config.json.
//! The defined thresholds are provided in bytes.
//!
//! ## False Positives
//!
//! ## False Negatives
//!
//! - At most one warning for stack memory allocation is created for each Function. This means multiple weaknesses
//! are not detected individually.

use crate::abstract_domain::DataDomain;
use crate::abstract_domain::IntervalDomain;
use crate::abstract_domain::RegisterDomain;
use crate::abstract_domain::TryToInterval;
use crate::analysis::pointer_inference::PointerInference;
use crate::analysis::vsa_results::*;
use crate::intermediate_representation::*;
use crate::pipeline::AnalysisResults;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::utils::symbol_utils::get_callsites;
use crate::utils::symbol_utils::get_symbol_map;
use crate::CweModule;
use serde::Deserialize;
use serde::Serialize;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE789",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct.
/// If a threshold is exceeded, the warning is generated.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    stack_threshold: u64,
    heap_threshold: u64,
    symbols: Vec<String>,
}

/// Determines if `def` is an assignment on the stackpointer.
fn is_assign_on_sp(def: &Def, sp: &Variable) -> bool {
    if let &Def::Assign { var, value: _ } = &def {
        if var == sp {
            return true;
        }
    }
    false
}

/// Determines if the interval holds values exceeding the threshold for stack allocations.
fn exceeds_threshold_on_stack(interval: DataDomain<IntervalDomain>, threshold: u64) -> bool {
    for rel_interval in interval.get_relative_values().values() {
        if let Ok(offset) = rel_interval.try_to_interval() {
            if let Ok(start) = offset.start.try_to_i128() {
                if start < -i128::from(threshold) {
                    return true;
                }
            }
        }
    }
    false
}

/// Determines if the interval holds values exceeding the threshold for heap allocations.
fn exceeds_threshold_on_call(interval: DataDomain<IntervalDomain>, threshold: u64) -> bool {
    if let Some(interval) = interval.get_absolute_value() {
        if let Ok(offset) = interval.try_to_interval() {
            if let Ok(end) = offset.end.try_to_u128() {
                if end > u128::from(threshold) {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if the multiplication of element count and size parameters exceeds the threshold.
fn multiply_args_for_calloc(
    pir: &PointerInference,
    jmp_tid: &Tid,
    parms: Vec<&Arg>,
) -> Option<DataDomain<IntervalDomain>> {
    if let (Some(nmeb), Some(size)) = (
        pir.eval_parameter_arg_at_call(jmp_tid, parms[0]),
        pir.eval_parameter_arg_at_call(jmp_tid, parms[1]),
    ) {
        return Some(nmeb.bin_op(BinOpType::IntMult, &size));
    }
    None
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(allocation: &Tid, is_stack_allocation: bool) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Large memory allocation) Potential{}memory exhaustion at 0x{}",
            match is_stack_allocation {
                true => " stack ",
                false => " heap ",
            },
            allocation.address
        ),
    )
    .tids(vec![format!("{allocation}")])
    .addresses(vec![allocation.address.clone()])
    .symbols(vec![])
}

/// Run the CWE check.
/// For each function, we check calls of the defined functions and instructions that
/// assign a value to the stackpointer.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();
    let pir = analysis_results.pointer_inference.unwrap();
    let symbol_map = get_symbol_map(project, &config.symbols);

    'functions: for sub in project.program.term.subs.values() {
        // Function call allocation case
        for (_, jump, symbol) in get_callsites(sub, &symbol_map) {
            if let Some(interval) = match symbol.name.as_str() {
                "calloc" => multiply_args_for_calloc(
                    pir,
                    &jump.tid,
                    vec![&symbol.parameters[0], &symbol.parameters[1]],
                ),
                "realloc" => pir.eval_parameter_arg_at_call(&jump.tid, &symbol.parameters[1]),
                _ => pir.eval_parameter_arg_at_call(&jump.tid, &symbol.parameters[0]),
            } {
                if exceeds_threshold_on_call(interval, config.heap_threshold) {
                    cwe_warnings.push(generate_cwe_warning(&jump.tid, false));
                }
            }
        }
        // Stack allocation case
        for blk in &sub.term.blocks {
            let assign_on_sp: Vec<&Term<Def>> = blk
                .term
                .defs
                .iter()
                .filter(|x| is_assign_on_sp(&x.term, &project.stack_pointer_register))
                .collect();
            for assign in assign_on_sp {
                if let Some(interval) = pir.eval_value_at_def(&assign.tid) {
                    if exceeds_threshold_on_stack(interval, config.stack_threshold) {
                        cwe_warnings.push(generate_cwe_warning(&assign.tid, true));
                        continue 'functions;
                    }
                }
            }
        }
    }
    cwe_warnings.dedup();

    (Vec::new(), cwe_warnings)
}
