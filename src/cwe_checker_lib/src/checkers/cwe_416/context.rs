use super::State;
use super::WarningContext;
use super::CWE_MODULE;
use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::AbstractIdentifier;
use crate::analysis::function_signature::FunctionSignature;
use crate::analysis::graph::Graph;
use crate::analysis::pointer_inference::PointerInference;
use crate::analysis::vsa_results::VsaResult;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::CweWarning;
use crate::utils::log::LogMessage;
use std::collections::BTreeMap;

/// The context struct for the fixpoint algorithm that contains references to the analysis results
/// of other analyses used in this analysis.
pub struct Context<'a> {
    /// A pointer to the project struct.
    pub project: &'a Project,
    /// A pointer to the control flow graph.
    pub graph: &'a Graph<'a>,
    /// A pointer to the results of the pointer inference analysis.
    pub pointer_inference: &'a PointerInference<'a>,
    /// A pointer to the computed function signatures for all internal functions.
    pub function_signatures: &'a BTreeMap<Tid, FunctionSignature>,
    /// A sender channel that can be used to collect context objects for CWEwarnings.
    pub cwe_warning_collector: crossbeam_channel::Sender<WarningContext>,
    /// A sender channel that can be used to collect log messages.
    pub log_collector: crossbeam_channel::Sender<LogMessage>,
    /// Generic function arguments assumed for calls to functions where the real number of parameters are unknown.
    generic_function_parameter: Vec<Arg>,
}

impl<'a> Context<'a> {
    /// Generate a new context struct from the given analysis results and a channel for gathering log messages and CWE warnings.
    pub fn new<'b>(
        analysis_results: &'b AnalysisResults<'a>,
        cwe_warning_collector: crossbeam_channel::Sender<WarningContext>,
        log_collector: crossbeam_channel::Sender<LogMessage>,
    ) -> Context<'a>
    where
        'a: 'b,
    {
        let generic_function_parameter: Vec<_> =
            if let Some(cconv) = analysis_results.project.get_standard_calling_convention() {
                cconv
                    .integer_parameter_register
                    .iter()
                    .map(|reg| Arg::from_var(reg.clone(), None))
                    .collect()
            } else {
                Vec::new()
            };
        Context {
            project: analysis_results.project,
            graph: analysis_results.control_flow_graph,
            pointer_inference: analysis_results.pointer_inference.unwrap(),
            function_signatures: analysis_results.function_signatures.unwrap(),
            cwe_warning_collector,
            log_collector,
            generic_function_parameter,
        }
    }

    /// For the given call parameters of the given call check for possible Use-After-Free bugs
    /// and return the possible causes for such bugs.
    fn collect_cwe_warnings_of_call_params<'b>(
        &self,
        state: &mut State,
        call_tid: &Tid,
        call_params: impl IntoIterator<Item = &'b Arg>,
    ) -> Option<Vec<(AbstractIdentifier, Tid)>> {
        let mut warnings = Vec::new();
        for arg in call_params {
            if let Some(arg_value) = self
                .pointer_inference
                .eval_parameter_arg_at_call(call_tid, arg)
            {
                if let Some(mut warning_causes) = state.check_address_for_use_after_free(&arg_value)
                {
                    warnings.append(&mut warning_causes);
                }
            }
        }
        if !warnings.is_empty() {
            Some(warnings)
        } else {
            None
        }
    }

    /// Check the parameters of an internal function call for dangling pointers and report CWE warnings accordingly.
    fn check_internal_call_params_for_use_after_free(
        &self,
        state: &mut State,
        callee_sub_tid: &Tid,
        call_tid: &Tid,
    ) {
        let function_signature = match self.function_signatures.get(callee_sub_tid) {
            Some(fn_sig) => fn_sig,
            None => return,
        };
        let mut warning_causes = Vec::new();
        for (arg, access_pattern) in &function_signature.parameters {
            if access_pattern.is_dereferenced() {
                if let Some(arg_value) = self
                    .pointer_inference
                    .eval_parameter_arg_at_call(call_tid, arg)
                {
                    if let Some(mut warnings) = state.check_address_for_use_after_free(&arg_value) {
                        warning_causes.append(&mut warnings);
                    }
                }
            }
        }
        let callee_sub_name = &self.project.program.term.subs[callee_sub_tid].term.name;
        if !warning_causes.is_empty() {
            self.generate_cwe_warning(
                "CWE416",
                format!(
                    "(Use After Free) Call to {} at {} may access dangling pointers through its parameters",
                    callee_sub_name,
                    call_tid.address
                ),
                call_tid,
                warning_causes,
                &state.current_fn_tid
            );
        }
    }

    /// Handle a call to `free` by marking the corresponding memory object IDs as dangling and detecting possible double frees.
    fn handle_call_to_free(&self, state: &mut State, call_tid: &Tid, free_symbol: &ExternSymbol) {
        if free_symbol.parameters.is_empty() {
            let error_msg = LogMessage::new_error("free symbol without parameter encountered.")
                .location(call_tid.clone())
                .source(CWE_MODULE.name);
            self.log_collector.send(error_msg).unwrap();
            return;
        }
        if let Some(param) = self
            .pointer_inference
            .eval_parameter_arg_at_call(call_tid, &free_symbol.parameters[0])
        {
            if let Some(pi_state) = self.pointer_inference.get_state_at_jmp_tid(call_tid) {
                if let Some(warning_causes) =
                    state.handle_param_of_free_call(call_tid, &param, pi_state)
                {
                    self.generate_cwe_warning(
                        "CWE415",
                        format!(
                            "(Double Free) Object may have been freed before at {}",
                            call_tid.address
                        ),
                        call_tid,
                        warning_causes,
                        &state.current_fn_tid,
                    );
                }
            }
        }
    }

    /// Generate a CWE warning and send it to the warning collector channel.
    fn generate_cwe_warning(
        &self,
        name: &str,
        description: String,
        location: &Tid,
        warning_causes: Vec<(AbstractIdentifier, Tid)>,
        root_function: &Tid,
    ) {
        let cwe_warning = CweWarning {
            name: name.to_string(),
            version: CWE_MODULE.version.to_string(),
            addresses: vec![location.address.clone()],
            tids: vec![format!("{location}")],
            symbols: Vec::new(),
            other: Vec::new(),
            description,
        };
        self.cwe_warning_collector
            .send(WarningContext::new(
                cwe_warning,
                warning_causes,
                root_function.clone(),
            ))
            .unwrap();
    }
}

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get a reference to the control flow graph.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge two node states.
    fn merge(&self, state1: &State, state2: &State) -> State {
        state1.merge(state2)
    }

    /// Check whether the `def` may access already freed memory.
    /// If yes, generate a CWE warning and mark the corresponding object IDs as already flagged.
    fn update_def(&self, state: &State, def: &Term<Def>) -> Option<State> {
        let mut state = state.clone();
        if let Some(address) = self.pointer_inference.eval_address_at_def(&def.tid) {
            if let Some(warning_causes) = state.check_address_for_use_after_free(&address) {
                self.generate_cwe_warning(
                    "CWE416",
                    format!(
                        "(Use After Free) Access through a dangling pointer at {}",
                        def.tid.address
                    ),
                    &def.tid,
                    warning_causes,
                    &state.current_fn_tid,
                );
            }
        }
        Some(state)
    }

    /// Just returns the unmodified state.
    fn update_jump(
        &self,
        state: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        Some(state.clone())
    }

    /// Check whether any call parameters are dangling pointers and generate CWE warnings accordingly.
    /// Always returns `None` since the analysis is a bottom-up analysis (i.e. no information flows from caller to callee).
    fn update_call(
        &self,
        state: &State,
        call: &Term<Jmp>,
        target: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        use crate::analysis::graph::Node;
        let sub = match *target {
            Node::BlkStart(_, sub) => sub,
            _ => return None,
        };
        let mut state = state.clone();
        self.check_internal_call_params_for_use_after_free(&mut state, &sub.tid, &call.tid);
        // No information flows from caller to callee, so we return `None` regardless.
        None
    }

    /// Collect the IDs of objects freed in the callee and mark the corresponding objects in the caller as freed.
    /// Also check the call parameters for Use-After-Frees.
    fn update_return(
        &self,
        state: Option<&State>,
        state_before_call: Option<&State>,
        call: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        let (state_before_return, state_before_call) = match (state, state_before_call) {
            (Some(state_before_return), Some(state_before_call)) => {
                (state_before_return, state_before_call)
            }
            _ => return None,
        };
        let id_replacement_map = match self
            .pointer_inference
            .get_id_renaming_map_at_call_tid(&call.tid)
        {
            Some(map) => map,
            None => return None,
        };
        let pi_state_before_call = match self.pointer_inference.get_state_at_jmp_tid(&call.tid) {
            Some(pi_state) => pi_state,
            None => return None,
        };

        let mut state_after_return = state_before_call.clone();
        // Check for Use-After-Frees through function parameters.
        // FIXME: This is actually done twice, since the `update_call` method uses the same check.
        // But to remove the check there we would have to know the callee function TID here
        // even in the case when the call does not actually return at all.
        self.check_internal_call_params_for_use_after_free(
            &mut state_after_return,
            &state_before_return.current_fn_tid,
            &call.tid,
        );
        // Add object IDs of objects that may have been freed in the callee.
        state_after_return.collect_freed_objects_from_called_function(
            state_before_return,
            id_replacement_map,
            &call.tid,
            pi_state_before_call,
        );
        Some(state_after_return)
    }

    /// Handle extern symbols by checking for Use-After-Frees in the call parameters.
    /// Also handle calls to `free` by marking the corresponding object ID as dangling.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        let mut state = state.clone();
        if let Some(extern_symbol) = match &call.term {
            Jmp::Call { target, .. } => self.project.program.term.extern_symbols.get(target),
            _ => None,
        } {
            match extern_symbol.name.as_str() {
                "free" => self.handle_call_to_free(&mut state, &call.tid, extern_symbol),
                extern_symbol_name => {
                    if let Some(warning_causes) = self.collect_cwe_warnings_of_call_params(
                        &mut state,
                        &call.tid,
                        &extern_symbol.parameters,
                    ) {
                        self.generate_cwe_warning(
                            "CWE416",
                            format!(
                                "(Use After Free) Call to {} at {} may access dangling pointers through its parameters",
                                extern_symbol_name,
                                call.tid.address
                                ),
                            &call.tid,
                            warning_causes,
                            &state.current_fn_tid,
                        );
                    }
                }
            }
        } else if let Some(warning_causes) = self.collect_cwe_warnings_of_call_params(
            &mut state,
            &call.tid,
            &self.generic_function_parameter,
        ) {
            self.generate_cwe_warning(
                "CWE416",
                format!(
                    "(Use After Free) Call at {} may access dangling pointers through its parameters",
                    call.tid.address
                    ),
                &call.tid,
                warning_causes,
                &state.current_fn_tid,
            );
        }
        Some(state)
    }

    /// Just returns the unmodified state
    fn specialize_conditional(
        &self,
        state: &State,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<State> {
        Some(state.clone())
    }
}
