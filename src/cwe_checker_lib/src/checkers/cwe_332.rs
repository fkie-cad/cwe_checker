//! This module implements a check for CWE-332: Insufficient Entropy in PRNG.
//!
//! This can happen, for instance, if the PRNG is not seeded. A classical example
//! would be calling rand without srand. This could lead to predictable random
//! numbers and could, for example, weaken crypto functionality.
//!
//! See <https://cwe.mitre.org/data/definitions/332.html> for a detailed description.
//!
//! ## How the check works
//!
//! For pairs of a secure seeding function and a corresponding random number generator function
//! (e.g. the pair `(srand, rand)`, configurable in `config.json`)
//! we check whether the program calls the random number generator without calling the seeding function.
//!
//! ## False Positives
//!
//! None known
//!
//! ## False Negatives
//!
//! - It is not checked whether the seeding function gets called before the random number generator function.

use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::find_symbol;
use crate::CweModule;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE332",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct contains pairs of symbol names,
/// where the first name is the name of a seeding function
/// and the second name is the name of a corresponding random number generator access function.
/// It is assumed that a program has to call the seeding function first
/// to ensure that the RNG does not generate predictable random numbers.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    pairs: Vec<(String, String)>,
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(secure_initializer_func: &str, rand_func: &str) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Insufficient Entropy in PRNG) program uses {rand_func} without calling {secure_initializer_func} before"),
    )
}

/// Run the CWE check. See the module-level description for more information.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();

    for (secure_initializer_func, rand_func) in config.pairs.iter() {
        if find_symbol(&project.program, rand_func).is_some()
            && find_symbol(&project.program, secure_initializer_func).is_none()
        {
            cwe_warnings.push(generate_cwe_warning(secure_initializer_func, rand_func));
        }
    }
    (Vec::new(), cwe_warnings)
}
