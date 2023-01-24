use crate::abstract_domain::BricksDomain;
use crate::analysis::function_signature::FunctionSignature;
use crate::analysis::graph::Graph;
use crate::analysis::pointer_inference::PointerInference;
use crate::analysis::string_abstraction::StringAbstraction;
use crate::intermediate_representation::Project;
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::BTreeMap;

/// A struct containing pointers to all known analysis results
/// that may be needed as input for other analyses and CWE checks.
#[derive(Clone, Copy)]
pub struct AnalysisResults<'a> {
    /// The content of the binary file
    pub binary: &'a [u8],
    /// The computed control flow graph of the program.
    pub control_flow_graph: &'a Graph<'a>,
    /// A pointer to the project struct
    pub project: &'a Project,
    /// The results of the function signature analysis if already computed.
    pub function_signatures: Option<&'a BTreeMap<Tid, FunctionSignature>>,
    /// The result of the pointer inference analysis if already computed.
    pub pointer_inference: Option<&'a PointerInference<'a>>,
    /// The result of the string abstraction if already computed.
    pub string_abstraction: Option<&'a StringAbstraction<'a, BricksDomain>>,
}

impl<'a> AnalysisResults<'a> {
    /// Create a new `AnalysisResults` struct with only the project itself known.
    pub fn new(
        binary: &'a [u8],
        control_flow_graph: &'a Graph<'a>,
        project: &'a Project,
    ) -> AnalysisResults<'a> {
        AnalysisResults {
            binary,
            control_flow_graph,
            project,
            function_signatures: None,
            pointer_inference: None,
            string_abstraction: None,
        }
    }

    /// Compute the function signatures for internal functions.
    pub fn compute_function_signatures(
        &self,
    ) -> (BTreeMap<Tid, FunctionSignature>, Vec<LogMessage>) {
        crate::analysis::function_signature::compute_function_signatures(
            self.project,
            self.control_flow_graph,
        )
    }

    /// Create a new `AnalysisResults` struct containing the given function signature analysis results.
    pub fn with_function_signatures(
        self,
        function_signatures: Option<&'a BTreeMap<Tid, FunctionSignature>>,
    ) -> AnalysisResults<'a> {
        AnalysisResults {
            function_signatures,
            ..self
        }
    }

    /// Compute the pointer inference analysis.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_pointer_inference(
        &'a self,
        config: &serde_json::Value,
        print_stats: bool,
    ) -> PointerInference<'a> {
        crate::analysis::pointer_inference::run(
            self,
            serde_json::from_value(config.clone()).unwrap(),
            false,
            print_stats,
        )
    }

    /// Create a new `AnalysisResults` struct containing the given pointer inference analysis results.
    pub fn with_pointer_inference<'b: 'a>(
        self,
        pi_results: Option<&'b PointerInference<'a>>,
    ) -> AnalysisResults<'b> {
        AnalysisResults {
            pointer_inference: pi_results,
            ..self
        }
    }

    /// Compute the string abstraction.
    /// As the string abstraction depends on the pointer inference, the
    /// pointer inference is also computed and put into the `AnalysisResults` struct.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_string_abstraction(
        &'a self,
        config: &serde_json::Value,
        pi_results: Option<&'a PointerInference<'a>>,
    ) -> StringAbstraction<BricksDomain> {
        crate::analysis::string_abstraction::run(
            self.project,
            self.control_flow_graph,
            pi_results.unwrap(),
            serde_json::from_value(config.clone()).unwrap(),
        )
    }

    /// Create a new `AnalysisResults` struct containing the given string abstraction results.
    pub fn with_string_abstraction<'b: 'a>(
        self,
        string_abstraction: Option<&'b StringAbstraction<'a, BricksDomain>>,
    ) -> AnalysisResults<'b> {
        AnalysisResults {
            string_abstraction,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::graph::get_program_cfg;
    use std::collections::HashSet;

    impl<'a> AnalysisResults<'a> {
        /// Mocks the `AnalysisResults` struct with a given project.
        /// Note that the function leaks memory!
        pub fn mock_from_project(project: &'a Project) -> AnalysisResults<'a> {
            let extern_subs =
                HashSet::from_iter(project.program.term.extern_symbols.keys().cloned());
            let graph = Box::new(get_program_cfg(&project.program, extern_subs));
            let graph: &'a Graph = Box::leak(graph);
            let binary: &'a Vec<u8> = Box::leak(Box::new(Vec::new()));
            let analysis_results = AnalysisResults::new(binary, graph, project);
            let (fn_sigs, _) = analysis_results.compute_function_signatures();
            let fn_sigs: &'a BTreeMap<_, _> = Box::leak(Box::new(fn_sigs));
            let analysis_results = analysis_results.with_function_signatures(Some(fn_sigs));
            analysis_results
        }
    }
}
