//! A fixpoint analysis that abstracts strings in the program using various string abstract domains.
//! These include the Character Inclusion Domain and Bricks Domain among others.

use std::collections::BTreeMap;

use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop},
    prelude::*,
    utils::log::{CweWarning, LogMessage, LogThreadMsg},
    AnalysisResults,
};

use super::{fixpoint::Computation, forward_interprocedural_fixpoint::GeneralizedContext};

mod context;
mod state;

use context::*;

const VERSION: &str = "0.1";

/// The name and version number of the "AbstractStrings" CWE check.
pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "AbstractStrings",
    version: VERSION,
    run: extract_string_abstraction_results,
};

/// Configurable parameters for the analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Names of extern functions that manipulate strings
    /// or could introduce new strings (e.g. scanf).
    pub string_symbols: Vec<String>,
    pub format_string_index: BTreeMap<String, usize>,
}

/// A wrapper struct for the string abstraction computation object.
pub struct StringAbstraction<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> {
    computation: Computation<GeneralizedContext<'a, Context<'a, T>>>,
    log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    /// The log messages and CWE warnings that have been generated during the string abstraction analysis.
    pub collected_logs: (Vec<LogMessage>, Vec<CweWarning>),
}

/// The entry point for the memory analysis check.
/// Does not actually compute anything
/// but just extracts the results of the already computed string abstract analysis.
pub fn extract_string_abstraction_results(
    _analysis_results: &AnalysisResults,
    _analysis_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    todo!()
}

#[cfg(test)]
pub mod tests;
