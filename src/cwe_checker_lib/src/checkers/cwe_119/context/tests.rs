use super::*;

impl<'a> Context<'a> {
    /// Create a mock context.
    /// Note that this function leaks memory!
    pub fn mock_x64() -> Context<'static> {
        let project = Box::new(Project::mock_x64());
        let project = Box::leak(project);
        let analysis_results = Box::new(AnalysisResults::mock_from_project(project));
        let analysis_results = Box::leak(analysis_results);
        let (log_collector, _) = crossbeam_channel::unbounded();

        Context::new(
            analysis_results.project,
            analysis_results.control_flow_graph,
            analysis_results.pointer_inference.unwrap(),
            analysis_results.function_signatures.unwrap(),
            analysis_results,
            log_collector,
        )
    }
}
