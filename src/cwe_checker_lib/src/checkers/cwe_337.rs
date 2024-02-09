//! @cleanup

use crate::analysis::graph::Node;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::find_symbol;
use crate::CweModule;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE337",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Sources of predictable pseudo-random numbers.
    sources: Vec<String>,
    /// Random number seeding functions.
    sinks: Vec<String>,
}

/// Check whether the given block calls the given TID.
/// If yes, return the TID of the jump term that contains the call.
fn blk_calls_tid(blk: &Term<Blk>, tid: &Tid) -> Option<Tid> {
    for jmp in blk.term.jmps.iter() {
        match &jmp.term {
            Jmp::Call { target, .. } if target == tid => {
                return Some(jmp.tid.clone());
            }
            _ => (),
        }
    }
    None
}

/// Generate a CWE warning for a CWE hit.
fn generate_cwe_warning(rng_sub: &Term<Sub>, rng_callsite: &Tid, seed_sub: &Term<Sub>, seed_callsite: &Tid) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "Call of {} at {} leads immetiately into call of {} at {}.",
            rng_sub.term.name, rng_callsite.address, seed_sub.term.name, seed_callsite.address, 
        ))
        .tids(vec![format!("{rng_callsite}"), format!("{seed_callsite}")])
        .addresses(vec![rng_callsite.address.clone(), seed_callsite.address.clone()])
        .symbols(vec![rng_sub.term.name.clone(), seed_sub.term.name.clone()])
}

pub fn check_cwe(
    analysis_results: &AnalysisResults,
    _cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let graph = analysis_results.control_flow_graph;
    
    // @hmm: probably do this in the future?
    // let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    // let _sources = config.sources.iter().cloned().collect();
    // let _sinks = config.sinks.iter().cloned().collect();
    
    let srand_tid = match find_symbol(&project.program, "srand") {
        Some((tid, _)) => tid.clone(),
        None => return (Vec::new(), Vec::new()), // srand is never called by the program
    };
    
    let time_tid = match find_symbol(&project.program, "time") {
        Some((tid, _)) => tid.clone(),
        None => return (Vec::new(), Vec::new()), // time is never called by the program
    };
    
    let mut cwe_warnings = Vec::new();
    for time_call_node in graph.node_indices() {
        if let Node::BlkEnd(time_call_block, time_subprocedure) = graph[time_call_node] {
            if let Some(time_callsite_tid) = blk_calls_tid(time_call_block, &time_tid) {
            
                if graph.neighbors(time_call_node).count() > 1 {
                    panic!("Malformed Control flow graph: More than one edge for extern function call")
                }
                
                
                let time_return_node = graph.neighbors(time_call_node).next().unwrap();
                
                if let Node::BlkStart(time_return_block, srand_subprocedure) = graph[time_return_node] { // @cleanup: Is this always true?
                    if let Some(srand_callsite_tid) = blk_calls_tid(time_return_block, &srand_tid) {
                        cwe_warnings.push(generate_cwe_warning(time_subprocedure, &time_callsite_tid, srand_subprocedure, &srand_callsite_tid));
                    }
                }
            }
        }
    }
    
    (Vec::new(), cwe_warnings)
}







