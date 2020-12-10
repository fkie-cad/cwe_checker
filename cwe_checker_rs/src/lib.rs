/*!
# cwe_checker_rs

Parts of the cwe_checker that are written in Rust.
*/

#[macro_use]
extern crate ocaml;

use crate::analysis::pointer_inference::PointerInference;
use crate::intermediate_representation::Project;
use crate::utils::log::{CweWarning, LogMessage};

pub mod abstract_domain;
pub mod analysis;
pub mod bil;
pub mod checkers;
pub mod ffi;
pub mod intermediate_representation;
pub mod pcode;
pub mod term;
pub mod utils;

mod prelude {
    pub use apint::Width;
    pub use serde::{Deserialize, Serialize};

    pub use crate::bil::{BitSize, Bitvector};
    pub use crate::intermediate_representation::ByteSize;
    pub use crate::intermediate_representation::{Term, Tid};
    pub use crate::AnalysisResults;
    pub use anyhow::{anyhow, Error};
}

/// The generic function signature for the main function of a CWE module
pub type CweModuleFn =
    fn(&AnalysisResults, &serde_json::Value) -> (Vec<LogMessage>, Vec<CweWarning>);

/// A structure containing general information about a CWE analysis module,
/// including the function to be called to run the analysis.
pub struct CweModule {
    pub name: &'static str,
    pub version: &'static str,
    pub run: CweModuleFn,
}

impl std::fmt::Display for CweModule {
    /// Print the module name and its version number.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, r#""{}": "{}""#, self.name, self.version)
    }
}

/// Get a list of all known analysis modules.
pub fn get_modules() -> Vec<&'static CweModule> {
    vec![
        &crate::checkers::cwe_190::CWE_MODULE,
        &crate::checkers::cwe_332::CWE_MODULE,
        &crate::checkers::cwe_367::CWE_MODULE,
        &crate::checkers::cwe_426::CWE_MODULE,
        &crate::checkers::cwe_467::CWE_MODULE,
        &crate::checkers::cwe_476::CWE_MODULE,
        &crate::checkers::cwe_560::CWE_MODULE,
        &crate::checkers::cwe_676::CWE_MODULE,
        &crate::checkers::cwe_782::CWE_MODULE,
        &crate::analysis::pointer_inference::CWE_MODULE,
    ]
}

/// A struct containing pointers to all known analysis results
/// that may be needed as input for other analyses and CWE checks.
#[derive(Clone, Copy)]
pub struct AnalysisResults<'a> {
    /// A pointer to the project struct
    pub project: &'a Project,
    /// The result of the pointer inference analysis if already computed.
    pub pointer_inference: Option<&'a PointerInference<'a>>,
}

impl<'a> AnalysisResults<'a> {
    /// Create a new `AnalysisResults` struct with only the project itself known.
    pub fn new(project: &'a Project) -> AnalysisResults<'a> {
        AnalysisResults {
            project,
            pointer_inference: None,
        }
    }

    /// Compute the pointer inference analysis.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_pointer_inference(&self, config: &serde_json::Value) -> PointerInference<'a> {
        crate::analysis::pointer_inference::run(
            self.project,
            serde_json::from_value(config.clone()).unwrap(),
            false,
        )
    }

    /// Create a new `AnalysisResults` struct containing the given pointer inference analysis results.
    pub fn set_pointer_inference<'b: 'a>(
        self,
        pi_results: Option<&'b PointerInference<'a>>,
    ) -> AnalysisResults<'b> {
        AnalysisResults {
            pointer_inference: pi_results,
            ..self
        }
    }
}
