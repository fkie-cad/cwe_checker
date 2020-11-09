/*!
# cwe_checker_rs

Parts of the cwe_checker that are written in Rust.
*/

#[macro_use]
extern crate ocaml;

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
    pub use anyhow::{anyhow, Error};
}

/// The generic function signature for the main function of a CWE module
pub type CweModuleFn = fn(&Project, &serde_json::Value) -> (Vec<LogMessage>, Vec<CweWarning>);

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
        &crate::checkers::cwe_467::CWE_MODULE,
        &crate::checkers::cwe_560::CWE_MODULE,
        &crate::checkers::cwe_782::CWE_MODULE,
        &crate::checkers::cwe_676::CWE_MODULE,
        &crate::analysis::pointer_inference::CWE_MODULE,
    ]
}
