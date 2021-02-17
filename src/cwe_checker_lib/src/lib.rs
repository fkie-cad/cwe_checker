/*!
# cwe_checker_rs

Parts of the cwe_checker that are written in Rust.
*/

use crate::analysis::graph::Graph;
use crate::analysis::pointer_inference::PointerInference;
use crate::intermediate_representation::Project;
use crate::utils::binary::RuntimeMemoryImage;
use crate::utils::log::{CweWarning, LogMessage};

pub mod abstract_domain;
pub mod analysis;
pub mod checkers;
pub mod intermediate_representation;
pub mod pcode;
pub mod utils;

mod prelude {
    pub use apint::Width;
    pub use serde::{Deserialize, Serialize};

    pub use crate::intermediate_representation::{Bitvector, ByteSize};
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
        &crate::checkers::cwe_78::CWE_MODULE,
        &crate::checkers::cwe_190::CWE_MODULE,
        &crate::checkers::cwe_215::CWE_MODULE,
        &crate::checkers::cwe_243::CWE_MODULE,
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
    /// The content of the binary file
    pub binary: &'a [u8],
    /// A representation of the runtime memory image of the binary.
    pub runtime_memory_image: &'a RuntimeMemoryImage,
    /// The computed control flow graph of the program.
    pub control_flow_graph: &'a Graph<'a>,
    /// A pointer to the project struct
    pub project: &'a Project,
    /// The result of the pointer inference analysis if already computed.
    pub pointer_inference: Option<&'a PointerInference<'a>>,
}

impl<'a> AnalysisResults<'a> {
    /// Create a new `AnalysisResults` struct with only the project itself known.
    pub fn new(
        binary: &'a [u8],
        runtime_memory_image: &'a RuntimeMemoryImage,
        control_flow_graph: &'a Graph<'a>,
        project: &'a Project,
    ) -> AnalysisResults<'a> {
        AnalysisResults {
            binary,
            runtime_memory_image,
            control_flow_graph,
            project,
            pointer_inference: None,
        }
    }

    /// Compute the pointer inference analysis.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_pointer_inference(&'a self, config: &serde_json::Value) -> PointerInference<'a> {
        crate::analysis::pointer_inference::run(
            self.project,
            self.runtime_memory_image,
            self.control_flow_graph,
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
