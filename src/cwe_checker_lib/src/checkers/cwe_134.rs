//! This module implements a check for CWE-134: Use of Externally-Controlled Format String.
//!
//! The software uses a function that accepts a format string as an argument,
//! but the format string originates from an external source.
//!
//! See <https://cwe.mitre.org/data/definitions/134.html> for a detailed description.
//!
//! ## How the check works
//!
//! Using forward dataflow analysis we search for external symbols that take a format string as an input parameter.
//! (e.g. sprintf). Then we check the content of the format string parameter and if it is not part of the global read only
//! memory of the binary, a CWE warning is generated.
//!
//! ### Symbols configurable in config.json
//!
//! - symbols that take a format string parameter.
//!
//! ## False Positives
//!
//! - The input was externally provided on purpose and originates from a trusted source.
//! - A pointer target could be lost but the format string was not externally provided.

use std::collections::HashMap;

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::abstract_domain::TryToBitvec;
use crate::analysis::graph::Edge;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::analysis::pointer_inference::PointerInference;
use crate::intermediate_representation::ExternSymbol;
use crate::intermediate_representation::Jmp;
use crate::intermediate_representation::RuntimeMemoryImage;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use crate::CweModule;

/// The module name and version
pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE134",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Config {
    /// The names of the system call symbols.
    format_string_symbols: Vec<String>,
    /// The index of the format string paramater of the symbol.
    format_string_index: HashMap<String, usize>,
}

/// The categorization of the string location based on kinds of different memory.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum StringLocation {
    /// Global read only memory
    GlobalReadable,
    /// Global read and write memory
    GlobalWriteable,
    /// Non Global memory
    NonGlobal,
    /// Unknown memory
    Unknown,
}

/// This check searches for external symbols that take a format string as an input parameter.
/// It then checks whether the parameter points to read only memory.
/// If not, a CWE warning is generated.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let format_string_symbols =
        crate::utils::symbol_utils::get_symbol_map(project, &config.format_string_symbols[..]);
    let format_string_index = config.format_string_index.clone();

    let pointer_inference_results = analysis_results.pointer_inference.unwrap();
    let mut cwe_warnings = Vec::new();

    for edge in pointer_inference_results.get_graph().edge_references() {
        if let Edge::ExternCallStub(jmp) = edge.weight() {
            if let Jmp::Call { target, .. } = &jmp.term {
                if let Some(symbol) = format_string_symbols.get(target) {
                    let location = locate_format_string(
                        &edge.source(),
                        symbol,
                        &format_string_index,
                        pointer_inference_results,
                        &analysis_results.project.runtime_memory_image,
                    );

                    if matches!(
                        location,
                        StringLocation::GlobalWriteable | StringLocation::NonGlobal
                    ) {
                        cwe_warnings.push(generate_cwe_warning(&jmp.tid, symbol, &location));
                    }
                }
            }
        }
    }

    (Vec::new(), cwe_warnings)
}

/// Returns a StringLocation based on the kind of memory
/// holding the string.
/// If no assumption about the string location can be made,
/// unknown is returned.
fn locate_format_string(
    node: &NodeIndex,
    symbol: &ExternSymbol,
    format_string_index: &HashMap<String, usize>,
    pointer_inference_results: &PointerInference,
    runtime_memory_image: &RuntimeMemoryImage,
) -> StringLocation {
    if let Some(NodeValue::Value(pi_state)) = pointer_inference_results.get_node_value(*node) {
        let format_string_parameter = symbol
            .parameters
            .get(*format_string_index.get(&symbol.name).unwrap())
            .unwrap();
        if let Ok(address) =
            pi_state.eval_parameter_arg(format_string_parameter, runtime_memory_image)
        {
            if let Ok(address_vector) = address.try_to_bitvec() {
                if runtime_memory_image.is_global_memory_address(&address_vector) {
                    if runtime_memory_image
                        .is_address_writeable(&address_vector)
                        .unwrap()
                    {
                        return StringLocation::GlobalWriteable;
                    }

                    return StringLocation::GlobalReadable;
                }
            }
        }
        return StringLocation::NonGlobal;
    }

    StringLocation::Unknown
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(
    callsite: &Tid,
    called_symbol: &ExternSymbol,
    location: &StringLocation,
) -> CweWarning {
    let description = match location {
        StringLocation::GlobalWriteable => {
            format!(
            "(Externally Controlled Format String) Potential externally controlled format string in global memory for call to {} at {}",
            called_symbol.name, callsite.address
        )
        }
        StringLocation::NonGlobal => {
            format!(
            "(Externally Controlled Format String) Potential externally controlled format string for call to {} at {}",
            called_symbol.name, callsite.address
        )
        }
        _ => panic!("Invalid String Location."),
    };
    CweWarning::new(CWE_MODULE.name, CWE_MODULE.version, description)
        .tids(vec![format!("{callsite}")])
        .addresses(vec![callsite.address.clone()])
        .symbols(vec![called_symbol.name.clone()])
}

#[cfg(test)]
pub mod tests {
    use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
    use crate::{defs, intermediate_representation::*};

    use super::*;

    fn mock_project() -> Project {
        let mut project = Project::mock_x64();
        let mut sub = Sub::mock("func");
        let mut block1 = Blk::mock_with_tid("block1");
        let block2 = Blk::mock_with_tid("block2");

        let mut defs = defs!["def2: RDI:8 = RBP:8 + 8:8", "def3: RSI:8 = 0x3002:8"];
        let jump = Jmp::call("call_string", "sprintf", Some("block2"));

        block1.term.defs.append(&mut defs);
        block1.term.jmps.push(jump);
        sub.term.blocks.push(block1);
        sub.term.blocks.push(block2);
        project.program.term.subs.insert(sub.tid.clone(), sub);
        project.program.term.entry_points.insert(Tid::new("func"));
        project
            .calling_conventions
            .insert("__stdcall".to_string(), CallingConvention::mock_x64());

        project
    }

    #[test]
    fn test_locate_format_string() {
        let sprintf_symbol = ExternSymbol::mock_sprintf_x64();
        let project = mock_project();
        let graph = crate::analysis::graph::get_program_cfg(&project.program);
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);
        let mut format_string_index: HashMap<String, usize> = HashMap::new();
        format_string_index.insert("sprintf".to_string(), 1);
        // Get the BlkEnd node with the function call.
        let node = graph
            .node_indices()
            .into_iter()
            .collect::<Vec<NodeIndex>>()
            .get(1)
            .unwrap()
            .clone();

        assert_eq!(
            locate_format_string(
                &node,
                &sprintf_symbol,
                &format_string_index,
                &pi_results,
                &project.runtime_memory_image,
            ),
            StringLocation::GlobalReadable
        );
    }
}
