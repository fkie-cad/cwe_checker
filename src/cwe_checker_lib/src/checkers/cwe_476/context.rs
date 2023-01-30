use super::State;
use super::Taint;
use super::CWE_MODULE;
use crate::abstract_domain::AbstractDomain;
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::graph::{Graph, Node};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::intermediate_representation::*;
use crate::utils::log::CweWarning;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::collections::HashMap;
use std::sync::Arc;

/// The context object for the Null-Pointer-Dereference check.
///
/// There is always only one source of taint for the analysis.
/// On creation of a `Context` object, the taint source is not set.
/// Starting the fixpoint algorithm without
/// [setting the taint source](Context::set_taint_source()) first will lead to a panic.
/// By resetting the taint source one can reuse the context object for several fixpoint computations.
#[derive(Clone)]
pub struct Context<'a> {
    /// A pointer to the corresponding project struct.
    project: &'a Project,
    /// A pointer to the results of the pointer inference analysis.
    /// They are used to determine the targets of pointers to memory,
    /// which in turn is used to keep track of taint on the stack or on the heap.
    pub pointer_inference_results: &'a PointerInferenceComputation<'a>,
    /// A map to get the node index of the `BlkStart` node containing a given [`Def`] as the first `Def` of the block.
    /// The keys are of the form `(Def-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    block_start_node_map: Arc<HashMap<(Tid, Tid), NodeIndex>>,
    /// Maps the TID of an extern symbol to the extern symbol struct.
    extern_symbol_map: Arc<HashMap<Tid, &'a ExternSymbol>>,
    /// A map to get the node index of the `BlkEnd` node containing a given [`Jmp`].
    /// The keys are of the form `(Jmp-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    jmp_to_blk_end_node_map: Arc<HashMap<(Tid, Tid), NodeIndex>>,
    /// The call whose return values are the sources for taint for the analysis.
    taint_source: Option<&'a Term<Jmp>>,
    /// The name of the function, whose return values are the taint sources.
    taint_source_name: Option<String>,
    /// The current subfunction.
    ///Since the analysis is intraprocedural,
    ///all nodes with state during the fixpoint algorithm should belong to this function.
    current_sub: Option<&'a Term<Sub>>,
    /// A channel where found CWE hits can be sent to.
    cwe_collector: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> Context<'a> {
    /// Create a new context object.
    ///
    /// Note that one has to set the taint source separately before starting the analysis!
    ///
    /// If one wants to run the analysis for several sources,
    /// one should clone or reuse an existing `Context` object instead of generating new ones,
    /// since this function can be expensive!
    pub fn new(
        project: &'a Project,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        let mut block_start_node_map = HashMap::new();
        let mut jmp_to_blk_end_node_map = HashMap::new();
        let graph = pointer_inference_results.get_graph();
        for (node_id, node) in graph.node_references() {
            match node {
                Node::BlkStart(block, sub) => {
                    if let Some(def) = block.term.defs.get(0) {
                        block_start_node_map.insert((def.tid.clone(), sub.tid.clone()), node_id);
                    }
                }
                Node::BlkEnd(block, sub) => {
                    for jmp in block.term.jmps.iter() {
                        jmp_to_blk_end_node_map.insert((jmp.tid.clone(), sub.tid.clone()), node_id);
                    }
                }
                _ => (),
            }
        }
        let mut extern_symbol_map = HashMap::new();
        for (tid, symbol) in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(tid.clone(), symbol);
        }
        Context {
            project,
            pointer_inference_results,
            block_start_node_map: Arc::new(block_start_node_map),
            extern_symbol_map: Arc::new(extern_symbol_map),
            jmp_to_blk_end_node_map: Arc::new(jmp_to_blk_end_node_map),
            taint_source: None,
            taint_source_name: None,
            current_sub: None,
            cwe_collector,
        }
    }

    /// Set the taint source and the current function for the analysis.
    pub fn set_taint_source(&mut self, taint_source: &'a Term<Jmp>, current_sub: &'a Term<Sub>) {
        let taint_source_name = match &taint_source.term {
            Jmp::Call { target, .. } => self
                .project
                .program
                .term
                .extern_symbols
                .get(target)
                .map(|symbol| symbol.name.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            _ => "Unknown".to_string(),
        };
        self.taint_source = Some(taint_source);
        self.taint_source_name = Some(taint_source_name);
        self.current_sub = Some(current_sub);
    }

    /// Get the current pointer inference state (if one can be found) for the given taint state.
    fn get_current_pointer_inference_state(
        &self,
        state: &State,
        tid: &Tid,
    ) -> Option<PointerInferenceState> {
        if let Some(pi_state) = state.get_pointer_inference_state() {
            Some(pi_state.clone())
        } else if let Some(node_id) = self
            .block_start_node_map
            .get(&(tid.clone(), self.current_sub.unwrap().tid.clone()))
        {
            match self.pointer_inference_results.get_node_value(*node_id) {
                Some(NodeValue::Value(val)) => Some(val.clone()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Update the pointer inference state contained in the given taint state
    /// according to the effect of the given `Def` term.
    fn update_pointer_inference_state(&self, state: &mut State, def: &Term<Def>) {
        if let Some(pi_state) = self.get_current_pointer_inference_state(state, &def.tid) {
            let pi_context = self.pointer_inference_results.get_context();
            let new_pi_state = pi_context.update_def(&pi_state, def);
            state.set_pointer_inference_state(new_pi_state);
        }
    }

    /// Generate a CWE warning for the taint source of the context object.
    fn generate_cwe_warning(&self, taint_access_location: &Tid) {
        let taint_source = self.taint_source.unwrap();
        let taint_source_name = self.taint_source_name.clone().unwrap();
        let cwe_warning = CweWarning::new(CWE_MODULE.name, CWE_MODULE.version,
            format!("(NULL Pointer Dereference) There is no check if the return value is NULL at {} ({}).",
            taint_source.tid.address, taint_source_name))
            .addresses(vec![taint_source.tid.address.clone(), taint_access_location.address.clone()])
            .tids(vec![format!("{}", taint_source.tid), format!("{taint_access_location}")])
            .symbols(vec![taint_source_name]);
        let _ = self.cwe_collector.send(cwe_warning);
    }

    /// Check parameters of an extern symbol for taint.
    /// For pointers as parameters we also check
    /// whether the pointer points directly to taint if it points to some stack address.
    /// or whether the pointed to object contains any taint at all if it is not a stack object.
    pub fn check_parameters_for_taint(
        &self,
        state: &State,
        extern_symbol: &ExternSymbol,
        node_id: NodeIndex,
    ) -> bool {
        // First check for taint directly in parameter registers (we don't need a pointer inference state for that)
        for parameter in extern_symbol.parameters.iter() {
            if let Arg::Register { expr, .. } = parameter {
                if state.eval(expr).is_tainted() {
                    return true;
                }
            }
        }
        if let Some(NodeValue::Value(pi_state)) =
            self.pointer_inference_results.get_node_value(node_id)
        {
            // Check stack parameters and collect referenced memory object that need to be checked for taint.
            for parameter in extern_symbol.parameters.iter() {
                match parameter {
                    Arg::Register { expr, .. } => {
                        let data = pi_state.eval(expr);
                        if state.check_if_address_points_to_taint(data, pi_state) {
                            return true;
                        }
                    }
                    Arg::Stack { address, size, .. } => {
                        if state
                            .load_taint_from_memory(&pi_state.eval(address), *size)
                            .is_tainted()
                        {
                            return true;
                        }
                        if let Ok(stack_param) = pi_state
                            .eval_parameter_arg(parameter, &self.project.runtime_memory_image)
                        {
                            if state.check_if_address_points_to_taint(stack_param, pi_state) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// If a possible  parameter register of the call contains taint,
    /// generate a CWE warning and return `None`.
    /// Else remove all taint contained in non-callee-saved registers.
    fn handle_generic_call(&self, state: &State, call_tid: &Tid) -> Option<State> {
        let pi_state_option = self.get_current_pointer_inference_state(state, call_tid);
        if state.check_generic_function_params_for_taint(self.project, pi_state_option.as_ref()) {
            self.generate_cwe_warning(call_tid);
            return None;
        }
        let mut new_state = state.clone();
        if let Some(calling_conv) = self.project.get_standard_calling_convention() {
            new_state.remove_non_callee_saved_taint(calling_conv);
        }
        Some(new_state)
    }
}

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the underlying graph of the fixpoint computation
    fn get_graph(&self) -> &Graph<'a> {
        self.pointer_inference_results.get_graph()
    }

    /// Merge two states
    fn merge(&self, state1: &State, state2: &State) -> State {
        state1.merge(state2)
    }

    /// Just returns a copy of the input state.
    fn specialize_conditional(
        &self,
        state: &State,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<State> {
        Some(state.clone())
    }

    /// Generate a CWE warning if taint may be contained in the function parameters.
    /// Always returns `None` so that the analysis stays intraprocedural.
    fn update_call(
        &self,
        state: &State,
        call: &Term<Jmp>,
        _target: &Node,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        let pi_state_option = self.get_current_pointer_inference_state(state, &call.tid);
        if state.check_generic_function_params_for_taint(self.project, pi_state_option.as_ref()) {
            self.generate_cwe_warning(&call.tid);
        }
        None
    }

    /// If taint may be contained in the function parameters, generate a CWE warning and return None.
    /// Else remove taint from non-callee-saved registers.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<Self::Value> {
        if state.is_empty() {
            return None;
        }
        match &call.term {
            Jmp::Call { target, .. } => {
                if let Some(extern_symbol) = self.extern_symbol_map.get(target) {
                    let blk_end_node_id = self
                        .jmp_to_blk_end_node_map
                        .get(&(call.tid.clone(), self.current_sub.unwrap().tid.clone()))
                        .unwrap();
                    if self.check_parameters_for_taint(state, extern_symbol, *blk_end_node_id) {
                        self.generate_cwe_warning(&call.tid);
                        return None;
                    }
                    let mut new_state = state.clone();
                    new_state.remove_non_callee_saved_taint(
                        self.project.get_calling_convention(extern_symbol),
                    );
                    Some(new_state)
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            Jmp::CallInd { .. } => self.handle_generic_call(state, &call.tid),
            _ => panic!("Malformed control flow graph encountered."),
        }
    }

    /// Update the taint state according to the effects of the given [`Def`].
    /// If tainted memory is accessed through a load or store instruction
    /// generate a CWE warning and return `None`.
    fn update_def(&self, state: &State, def: &Term<Def>) -> Option<Self::Value> {
        if state.is_empty() {
            // Without taint there is nothing to propagate.
            return None;
        }
        let mut new_state = state.clone();
        match &def.term {
            Def::Assign { var, value } => {
                new_state.set_register_taint(var, state.eval(value));
            }
            Def::Load { var, address } => {
                if state.eval(address).is_tainted() {
                    self.generate_cwe_warning(&def.tid);
                    return None;
                } else if let Some(pi_state) =
                    self.get_current_pointer_inference_state(state, &def.tid)
                {
                    let address_data = pi_state.eval(address);
                    let taint = state.load_taint_from_memory(&address_data, var.size);
                    new_state.set_register_taint(var, taint);
                } else {
                    new_state.set_register_taint(var, Taint::Top(var.size));
                }
            }
            Def::Store { address, value } => {
                if state.eval(address).is_tainted() {
                    self.generate_cwe_warning(&def.tid);
                    return None;
                } else if let Some(pi_state) =
                    self.get_current_pointer_inference_state(state, &def.tid)
                {
                    let address_data = pi_state.eval(address);
                    let taint = state.eval(value);
                    new_state.save_taint_to_memory(&address_data, taint);
                } else {
                    // We lost all knowledge about memory pointers.
                    // We delete all memory taint to reduce false positives.
                    new_state.remove_all_memory_taints();
                }
            }
        }
        self.update_pointer_inference_state(&mut new_state, def);
        Some(new_state)
    }

    /// Update the state according to a jump instruction.
    /// Checks whether the jump or the untaken conditional jump is a `CBranch` instruction
    /// which checks a tainted value.
    /// If yes, we assume that the taint source was correctly checked for being a Null pointer and return `None`.
    /// If no we only remove the `pointer_inference_state` from the state.
    fn update_jump(
        &self,
        state: &State,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<Self::Value> {
        if state.is_empty() {
            // Without taint there is nothing to propagate.
            return None;
        }
        if let Jmp::CBranch { condition, .. } = &jump.term {
            if state.eval(condition).is_tainted() {
                return None;
            }
        }
        if let Some(untaken_jump) = untaken_conditional {
            if let Jmp::CBranch { condition, .. } = &untaken_jump.term {
                if state.eval(condition).is_tainted() {
                    return None;
                }
            }
        }
        let mut new_state = state.clone();
        new_state.set_pointer_inference_state(None);
        Some(new_state)
    }

    /// If `state_before_return` is set and contains taint,
    /// generate a CWE warning (since the function may return a Null pointer in this case).
    /// If `state_before_call` is set, handle it like a generic extern function call
    /// (see [`update_call_stub`](Context::update_call_stub()) for more).
    fn update_return(
        &self,
        state_before_return: Option<&State>,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        if let Some(state) = state_before_return {
            // If taint is returned, generate a CWE warning
            let pi_state_option = self.get_current_pointer_inference_state(state, &return_term.tid);
            if state.check_return_values_for_taint(self.project, pi_state_option.as_ref()) {
                self.generate_cwe_warning(&return_term.tid);
            }
            // Do not return early in case `state_before_call` is also set (possible for recursive functions).
        }
        if let Some(state) = state_before_call {
            self.handle_generic_call(state, &call_term.tid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{def, expr, variable};

    impl<'a> Context<'a> {
        pub fn mock(
            project: &'a Project,
            pi_results: &'a PointerInferenceComputation<'a>,
        ) -> Context<'a> {
            let (cwe_sender, _) = crossbeam_channel::unbounded();
            let mut context = Context::new(project, pi_results, cwe_sender);
            let taint_source = Box::new(Term {
                tid: Tid::new("taint_source"),
                term: Jmp::Call {
                    target: Tid::new("malloc"),
                    return_: None,
                },
            });
            let taint_source = Box::leak(taint_source);
            let current_sub = Box::new(Sub::mock("current_sub"));
            let current_sub = Box::leak(current_sub);
            context.set_taint_source(taint_source, current_sub);
            context
        }
    }

    #[test]
    fn check_parameter_arg_for_taint() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let (mut state, _pi_state) = State::mock_with_pi_state();

        assert_eq!(
            context.check_parameters_for_taint(
                &state,
                &ExternSymbol::mock_x64("mock_symbol"),
                NodeIndex::new(0)
            ),
            false
        );

        state.set_register_taint(&variable!("RDI:8"), Taint::Tainted(ByteSize::new(8)));
        assert_eq!(
            context.check_parameters_for_taint(
                &state,
                &ExternSymbol::mock_x64("mock_symbol"),
                NodeIndex::new(0)
            ),
            true
        );
    }

    #[test]
    fn handle_generic_call() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let mut state = State::mock();

        assert!(context
            .handle_generic_call(&state, &Tid::new("call_tid"))
            .is_some());

        state.set_register_taint(&variable!("RDX:8"), Taint::Tainted(ByteSize::new(8)));
        assert!(context
            .handle_generic_call(&state, &Tid::new("call_tid"))
            .is_none());
    }

    #[test]
    fn update_def() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let (mut state, pi_state) = State::mock_with_pi_state();
        state.set_pointer_inference_state(Some(pi_state));

        let assign_def = def!["def: RCX:8 = RAX:8"];
        let result = context.update_def(&state, &assign_def).unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_tainted());
        assert!(result.eval(&expr!("RSP:8")).is_top());

        let load_def = def!["def: RCX:8 := Load from RSP:8"];

        let result = context.update_def(&state, &load_def).unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_tainted());
        assert!(result.eval(&expr!("RSP:8")).is_top());

        let store_def = def!["def: Store at RSP:8 := RCX:8"];
        let result = context.update_def(&state, &store_def).unwrap();
        let result = context.update_def(&result, &load_def).unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_top());
    }

    #[test]
    fn update_jump() {
        let project = Project::mock_x64();
        let pi_results = PointerInferenceComputation::mock(&project);
        let context = Context::mock(&project, &pi_results);
        let (state, _pi_state) = State::mock_with_pi_state();

        let jump = Term {
            tid: Tid::new("jmp"),
            term: Jmp::CBranch {
                target: Tid::new("target"),
                condition: expr!("RAX:8"),
            },
        };
        assert!(context
            .update_jump(&state, &jump, None, &Blk::mock())
            .is_none());
        let jump = Term {
            tid: Tid::new("jmp"),
            term: Jmp::CBranch {
                target: Tid::new("target"),
                condition: expr!("RBX:8"),
            },
        };
        assert!(context
            .update_jump(&state, &jump, None, &Blk::mock())
            .is_some());
    }
}
