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
//! that the [Pointer Inference analysis](crate::analysis::pointer_inference) could not track,
//! the analysis may miss a correct NULL pointer check and thus generate false positives.
//! - The analysis is intraprocedural.
//! If a parameter to a function is a potential NULL pointer,
//! this gets flagged as a CWE hit even if the function may expect NULL pointers in its parameters.
//! If a function returns a potential NULL pointer this gets flagged as a CWE hit,
//! although the function may be supposed to return potential NULL pointers.
//!
//! ## False Negatives
//!
//! - We do not check whether an access to a potential NULL pointer happens regardless
//! of a prior check.
//! - We do not check whether the conditional jump instruction checks specifically
//! for the return value being NULL or something else
//! - For functions with more than one return value we do not distinguish between
//! the return values.

use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::graph::{Edge, Node};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::CweModule;
use petgraph::visit::EdgeRef;
use std::collections::BTreeMap;

mod state;
use state::*;

mod taint;
pub use taint::*;

mod context;
use context::*;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE476",
    version: "0.3",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// The names of symbols for which the analysis should check
    /// whether the return values are checked for being a Null pointer by the analysed binary.
    symbols: Vec<String>,
}

/// Run the CWE check.
/// We check whether the return values of symbols configurable in the config file are being checked for Null pointers
/// before any memory access (and thus potential Null pointer dereferences) through these values happen.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pointer_inference_results = analysis_results.pointer_inference.unwrap();

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let symbol_map = crate::utils::symbol_utils::get_symbol_map(project, &config.symbols[..]);
    let general_context = Context::new(project, pointer_inference_results, cwe_sender);

    for edge in general_context.get_graph().edge_references() {
        if let Edge::ExternCallStub(jmp) = edge.weight() {
            if let Jmp::Call { target, .. } = &jmp.term {
                if let Some(symbol) = symbol_map.get(target) {
                    let node = edge.target();
                    let current_sub = match general_context.get_graph()[node] {
                        Node::BlkStart(_blk, sub) => sub,
                        _ => panic!(),
                    };
                    let mut context = general_context.clone();
                    context.set_taint_source(jmp, current_sub);
                    let pi_state_at_taint_source =
                        match pointer_inference_results.get_node_value(node) {
                            Some(NodeValue::Value(val)) => Some(val.clone()),
                            _ => None,
                        };
                    let mut computation = create_computation(context, None);
                    computation.set_node_value(
                        node,
                        NodeValue::Value(State::new(symbol, pi_state_at_taint_source.as_ref())),
                    );
                    computation.compute_with_max_steps(100);
                }
            }
        }
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
