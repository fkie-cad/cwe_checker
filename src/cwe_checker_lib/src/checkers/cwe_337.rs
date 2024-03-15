//! This module implements a check for CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)
//!
//! The use of predictable seeds significantly reduces the number of possible seeds that an attacker would need
//! to test in order to predict which random numbers will be generated by the PRNG.
//!
//! See <https://cwe.mitre.org/data/definitions/337.html> for a detailed description.
//!
//! ## How the check works
//!
//! Using dataflow analysis we search for an execution path where the result of a time source, like `time`,
//! is used as an argument to a PRNG seeding function, like `srand`.
//!
//! ### Symbols configurable in config.json
//!
//! Both the sources of predictable seeds and the seeding functions can be configured using the `sources`
//! and `seeding_functions` respectively.

use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::graph::{Edge, Graph, HasCfg};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::analysis::pointer_inference::{
    Data as PiData, PointerInference as PointerInferenceComputation,
};
use crate::analysis::taint::{state::State as TaState, TaintAnalysis};
use crate::analysis::vsa_results::{HasVsaResult, VsaResult};
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::{
    log::{CweWarning, LogMessage},
    symbol_utils,
};
use crate::CweModule;

use petgraph::visit::EdgeRef;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::AsRef;

/// The module name and version.
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE337",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Sources of predictable seeds.
    sources: Vec<String>,
    /// Random number seeding functions.
    seeding_functions: Vec<String>,
}

/// Run the CWE check.
///
/// We check if a return value of any of the sources (as determined by the
/// config file) is used as a direct parameter of any of the sinks (as
/// determined by the config file).
///
/// Currently, this is only used to detect whether a call of `time` leads into a
/// call of `srand`.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone())
        .expect("Invalid configuration inside config.json for CWE337.");

    let source_map = symbol_utils::get_symbol_map(project, &config.sources[..]);
    let sink_map = symbol_utils::get_symbol_map(project, &config.seeding_functions[..]);
    if source_map.is_empty() || sink_map.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let pi_result = analysis_results.pointer_inference.unwrap();
    let graph = analysis_results.control_flow_graph;
    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded();

    let context = Context {
        project: analysis_results.project,
        pi_result,
        control_flow_graph: graph,
        sink_map,
        extern_symbol_map: project
            .program
            .term
            .extern_symbols
            .iter()
            .map(|(tid, sym)| (tid.clone(), sym))
            .collect(),
        cwe_collector: cwe_sender,
    };
    let mut computation = create_computation(context, None);

    for edge in graph.edge_references() {
        let Edge::ExternCallStub(jmp) = edge.weight() else {
            continue;
        };
        let Jmp::Call { target, .. } = &jmp.term else {
            continue;
        };
        let Some(symbol) = source_map.get(target) else {
            continue;
        };
        let return_node = edge.target();

        computation.set_node_value(
            return_node,
            NodeValue::Value(TaState::new_return(symbol, pi_result, return_node)),
        );
    }

    // FIXME: This number should be in the config.
    computation.compute_with_max_steps(100);

    let mut cwe_warnings = BTreeMap::new();
    for cwe in cwe_receiver.try_iter() {
        cwe_warnings.insert(cwe.addresses[0].clone(), cwe);
    }
    let cwe_warnings = cwe_warnings.into_values().collect();

    (Vec::new(), cwe_warnings)
}

/// The Context struct for the taint analysis.
pub struct Context<'a> {
    /// A pointer to the corresponding project struct.
    project: &'a Project,
    /// A pointer to the results of the pointer inference analysis.
    ///
    /// They are used to determine the targets of pointers to memory, which in
    /// turn is used to keep track of taint on the stack or on the heap.
    pi_result: &'a PointerInferenceComputation<'a>,
    /// The underlying control flow graph for the algorithm.
    control_flow_graph: &'a Graph<'a>,
    /// A map of symbols to use as sinks for the algorithm.
    sink_map: HashMap<Tid, &'a ExternSymbol>,
    /// Maps the TID of an extern symbol to the extern symbol struct.
    extern_symbol_map: HashMap<Tid, &'a ExternSymbol>,
    /// A channel where found CWE hits can be sent to.
    cwe_collector: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> HasCfg<'a> for Context<'a> {
    fn get_cfg(&self) -> &Graph<'a> {
        self.control_flow_graph
    }
}

impl<'a> HasVsaResult<PiData> for Context<'a> {
    fn vsa_result(&self) -> &impl VsaResult<ValueDomain = PiData> {
        self.pi_result
    }
}

impl<'a> AsRef<Project> for Context<'a> {
    fn as_ref(&self) -> &Project {
        self.project
    }
}

impl<'a> TaintAnalysis<'a> for Context<'a> {
    /// Generate a CWE warning if taint may be contained in the arguments to a
    /// sink function.
    ///
    /// If this is a call to a sink function and the passed arguments may
    /// contain taint we generate a CWE waning and return `None` to suppress
    /// the generation of further warnings. Else we just clear the taint from
    /// all non-caller-saved registers.
    fn update_call_stub(&self, state: &TaState, call: &Term<Jmp>) -> Option<TaState> {
        if state.is_empty() {
            return None;
        }

        match &call.term {
            Jmp::Call { target, .. } => {
                if let Some(sink_symbol) = self.sink_map.get(target) {
                    if state.check_extern_parameters_for_taint::<true>(
                        self.vsa_result(),
                        sink_symbol,
                        &call.tid,
                    ) {
                        self.generate_cwe_warning(call, sink_symbol);

                        None
                    } else {
                        Some(self.update_extern_symbol(state, sink_symbol))
                    }
                } else {
                    let extern_symbol = self
                        .extern_symbol_map
                        .get(target)
                        .expect("Extern symbol not found.");

                    Some(self.update_extern_symbol(state, extern_symbol))
                }
            }
            Jmp::CallInd { .. } => self.update_call_generic(state, &call.tid, &None),
            _ => panic!("Malformed control flow graph encountered."),
        }
    }
}

impl<'a> Context<'a> {
    /// Transition function for calls to external functions that do not
    /// trigger a CWE warning, i.e., its not a sink function or no taint is in
    /// the arguments.
    fn update_extern_symbol(&self, state: &TaState, extern_symbol: &ExternSymbol) -> TaState {
        let mut new_state = state.clone();

        new_state.remove_non_callee_saved_taint(self.project.get_calling_convention(extern_symbol));

        new_state
    }

    fn generate_cwe_warning(&self, sink_call: &Term<Jmp>, sink_symbol: &ExternSymbol) {
        let cwe_warning = CweWarning::new(
            CWE_MODULE.name,
            CWE_MODULE.version,
            format!(
                "RNG seed function {} at {} is seeded with predictable seed source.",
                sink_symbol.name, sink_call.tid.address,
            ),
        )
        .tids(vec![format!("{}", sink_call.tid)])
        .addresses(vec![sink_call.tid.address.clone()])
        .symbols(vec![sink_symbol.name.clone()]);
        let _ = self.cwe_collector.send(cwe_warning);
    }
}
