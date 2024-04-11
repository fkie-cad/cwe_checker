//! This module implements a check for CWE-476: NULL Pointer Dereference.
//!
//! Functions like `malloc()` may return NULL values instead of pointers to indicate
//! failed calls. If one tries to access memory through this return value without
//! checking it for being NULL first, this can crash the program.
//!
//! See <https://cwe.mitre.org/data/definitions/476.html> for a detailed description.
//!
//! ## How the check works
//!
//! Using dataflow analysis we search for an execution path where a memory access using the return value of
//! a symbol happens before the return value is checked through a conditional jump instruction.
//!
//! ### Symbols configurable in config.json
//!
//! The symbols are the functions whose return values are assumed to be potential
//! NULL pointers.
//!
//! ## False Positives
//!
//! - If a possible NULL pointer is temporarily saved in a memory location
//!   that the [Pointer Inference analysis](crate::analysis::pointer_inference)
//!   could not track, the analysis may miss a correct NULL pointer check and
//!   thus generate false positives.
//! - The analysis is intraprocedural. If a parameter to a function is a
//!   potential NULL pointer, this gets flagged as a CWE hit even if the
//!   function may expect NULL pointers in its parameters. If a function returns
//!   a potential NULL pointer this gets flagged as a CWE hit, although the
//!   function may be supposed to return potential NULL pointers.
//!
//! ## False Negatives
//!
//! - We do not check whether an access to a potential NULL pointer happens
//!   regardless of a prior check.
//! - We do not check whether the conditional jump instruction checks
//!   specifically for the return value being NULL or something else
//! - For functions with more than one return value we do not distinguish between
//!   the return values.

use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::graph::Edge;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::analysis::taint::state::State as TaState;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::{
    log::{CweWarning, LogMessage},
    symbol_utils,
};
use crate::CweModule;
use petgraph::visit::EdgeRef;
use std::collections::BTreeMap;

mod context;

use context::*;

/// The module name and version.
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE476",
    version: "0.3",
    run: check_cwe,
};

/// The configuration struct.
///
/// These values are configurable via the `config.json` and `lkm_config.json`
/// files.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// If `true`, passing a tainted value, or a pointer to an object that
    /// contains taint, as an argument to a function call is more likely to
    /// cause a warning.
    strict_call_policy: bool,
    /// Threshold for the fixpoint computation.
    max_steps: u64,
    /// The names of symbols for which the analysis should check whether the
    /// return values are checked for being a NULL pointer by the analysed
    /// binary.
    symbols: Vec<String>,
}

/// Run the CWE check.
///
/// We check whether the return values of symbols configurable in the config
/// file are being checked for NULL pointers before any memory access (and thus
/// potential NULL pointer dereferences) through these values can happen.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pi_result = analysis_results.pointer_inference.unwrap();

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let symbol_map = symbol_utils::get_symbol_map(project, &config.symbols[..]);
    let general_context = Context::new(&config, project, pi_result, cwe_sender);

    for edge in general_context.get_graph().edge_references() {
        let Edge::ExternCallStub(jmp) = edge.weight() else {
            continue;
        };
        let Jmp::Call { target, .. } = &jmp.term else {
            continue;
        };
        let Some(symbol) = symbol_map.get(target) else {
            continue;
        };
        let return_node = edge.target();

        let mut context = general_context.clone();
        context.set_taint_source(jmp);

        let mut computation = create_computation(context, None);
        computation.set_node_value(
            return_node,
            NodeValue::Value(TaState::new_return(symbol, pi_result, return_node)),
        );
        computation.compute_with_max_steps(config.max_steps);
    }

    let mut cwe_warnings = BTreeMap::new();
    for cwe in cwe_receiver.try_iter() {
        match &cwe.addresses[..] {
            [taint_source_address, ..] => cwe_warnings.insert(taint_source_address.clone(), cwe),
            _ => panic!(),
        };
    }
    let cwe_warnings = cwe_warnings.into_values().collect();

    (Vec::new(), cwe_warnings)
}
