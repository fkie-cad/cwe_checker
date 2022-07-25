//! This module implements a check for CWE-789: Memory Allocation with Excessive Size Value.
//!
//! Only stack memory allocation is covered in this module.
//! Excessive allocation of memory might destabilize programs on machines with limited resources.
//!
//! See <https://cwe.mitre.org/data/definitions/789.html> for a detailed description.
//!
//! ## How the check works
//!
//! Every instruction is checked if it assigns a new value to the stackpointer. If
//! this is the case, the value range of the assignment is checked and if it
//! exceeds the defined threshold defined in config.json, a warning is generated.
//!
//! ## False Negatives
//!
//! -CWE789 covers calls to function like malloc for large amounts of memory, too.
//! these cases are not covered by this module.

use crate::abstract_domain::DataDomain;
use crate::abstract_domain::IntervalDomain;
use crate::abstract_domain::TryToInterval;
use crate::analysis::vsa_results::*;
use crate::intermediate_representation::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::AnalysisResults;
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
/// If `threshold` is exceeded, the warning is generated.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    threshold: u64,
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

/// Determines if the interval holds values exceeding the threshold.
fn exceeds_threshold(interval: DataDomain<IntervalDomain>, threshold: u64) -> bool {
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

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(allocation: &Tid) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Large memory allocation) Potential stack memory exhaustion at {}",
            allocation
        ),
    )
    .tids(vec![format!("{}", allocation)])
    .addresses(vec![allocation.address.clone()])
    .symbols(vec![])
}

/// Run the CWE check.
/// For each instruction we check if an assignment to the stackpointer
/// exceeds the threshold defined in config.json.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();

    for sub in project.program.term.subs.values() {
        for blk in &sub.term.blocks {
            let subs_on_sp: Vec<&Term<Def>> = blk
                .term
                .defs
                .iter()
                .filter(|x| is_assign_on_sp(&x.term, &project.stack_pointer_register))
                .collect();
            for assign in subs_on_sp {
                if let Some(interval) = analysis_results
                    .pointer_inference
                    .unwrap()
                    .eval_value_at_def(&assign.tid)
                {
                    if exceeds_threshold(interval, config.threshold) {
                        cwe_warnings.push(generate_cwe_warning(&sub.tid));
                    }
                }
            }
        }
    }
    cwe_warnings.dedup();

    (Vec::new(), cwe_warnings)
}
