use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use petgraph::graph::NodeIndex;

use super::{state::State, BlockMaps, SymbolMaps, CWE_MODULE};
use crate::{
    abstract_domain::{AbstractDomain, DataDomain, IntervalDomain},
    analysis::{
        forward_interprocedural_fixpoint::Context as PiContext, graph::Graph,
        pointer_inference::PointerInference as PointerInferenceComputation,
        pointer_inference::State as PointerInferenceState,
    },
    checkers::cwe_476::Taint,
    intermediate_representation::*,
    utils::{binary::RuntimeMemoryImage, log::CweWarning},
};

pub mod parameter_detection;

#[derive(Clone)]
pub struct Context<'a> {
    /// A pointer to the corresponding project struct.
    project: &'a Project,
    /// A pointer to the representation of the runtime memory image.
    runtime_memory_image: &'a RuntimeMemoryImage,
    /// The reversed control flow graph for the analysis
    graph: Arc<Graph<'a>>,
    /// A pointer to the results of the pointer inference analysis.
    /// They are used to determine the targets of pointers to memory,
    /// which in turn is used to keep track of taint on the stack or on the heap.
    pub pointer_inference_results: &'a PointerInferenceComputation<'a>,
    /// - block_first_def_set:
    ///       - A set containing a given [`Def`] as the first `Def` of the block.
    ///       The keys are of the form `(Def-TID, Current-Sub-TID)`
    ///       to distinguish the nodes for blocks contained in more than one function.
    /// - block_start_last_def_map:
    ///       - A map to get the node index of the `BlkStart` node containing a given [`Def`] as the last `Def` of the block.
    ///       The keys are of the form `(Def-TID, Current-Sub-TID)`
    ///       to distinguish the nodes for blocks contained in more than one function.
    /// - jmp_to_blk_end_node_map:
    ///       - A map to get the node index of the `BlkEnd` node containing a given [`Jmp`].
    ///       The keys are of the form `(Jmp-TID, Current-Sub-TID)`
    ///       to distinguish the nodes for blocks contained in more than one function.
    block_maps: Arc<BlockMaps>,
    /// - string_symbols:
    ///     - Maps the TID of an extern string related symbol to the corresponding extern symbol struct.
    /// - user_input_symbols:
    ///     - Maps the TID of an extern symbol that take input from the user to the corresponding extern symbol struct.
    /// - extern_symbol_map:
    ///     - Maps the TID of an extern symbol to the extern symbol struct.
    symbol_maps: Arc<SymbolMaps<'a>>,
    /// The call whose parameter values are the sources for taint for the analysis.
    pub taint_source: Option<&'a Term<Jmp>>,
    /// The subroutine from which the taint source originates
    pub taint_source_sub: Option<&'a Term<Sub>>,
    /// The name of the function, whose parameter values are the taint sources.
    pub taint_source_name: Option<String>,
    /// A channel where found CWE hits can be sent to.
    cwe_collector: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> Context<'a> {
    /// Creates a new context for the CWE 78 taint analysis.
    pub fn new(
        project: &'a Project,
        runtime_memory_image: &'a RuntimeMemoryImage,
        graph: Arc<Graph<'a>>,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        symbol_maps: Arc<SymbolMaps<'a>>,
        block_maps: Arc<BlockMaps>,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        Context {
            project,
            runtime_memory_image,
            graph,
            pointer_inference_results,
            symbol_maps,
            block_maps,
            taint_source: None,
            taint_source_sub: None,
            taint_source_name: None,
            cwe_collector,
        }
    }

    /// Generates the CWE Warning for the CWE 78 check
    pub fn generate_cwe_warning(&self, sub_name: &str) {
        let source = self.taint_source.unwrap();
        let name = self.taint_source_name.clone().unwrap();
        let description: String = format!(
            "(Potential OS Command Injection) Input for call to {} is not properly sanitized in function {} ({})",
            name, sub_name, source.tid.address,
        );
        let cwe_warning = CweWarning::new(
            String::from(CWE_MODULE.name),
            String::from(CWE_MODULE.version),
            description,
        )
        .addresses(vec![source.tid.address.clone()])
        .tids(vec![format!("{}", source.tid)])
        .symbols(vec![String::from(sub_name)])
        .other(vec![vec![String::from("OS Command Injection"), name]]);
        let _ = self.cwe_collector.send(cwe_warning);
    }

    /// Set the taint source and the current function for the analysis.
    pub fn set_taint_source(
        &mut self,
        taint_source: &'a Term<Jmp>,
        taint_source_symbol_name: &str,
        taint_source_sub: &'a Term<Sub>,
    ) {
        self.taint_source = Some(taint_source);
        self.taint_source_sub = Some(taint_source_sub);
        self.taint_source_name = Some(taint_source_symbol_name.to_string());
    }

    /// Returns the pointer inference graph
    pub fn get_pi_graph(&self) -> &Graph<'a> {
        self.pointer_inference_results.get_graph()
    }

    /// Checks whether the firt parameter of a string related function points to a taint.
    /// If so, removes the taint at the target memory.
    pub fn first_param_points_to_memory_taint(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State,
        parameter: &Arg,
    ) -> bool {
        let mut points_to_memory_taint: bool = false;
        if let Ok(address) = pi_state.eval_parameter_arg(
            parameter,
            &self.project.stack_pointer_register,
            self.runtime_memory_image,
        ) {
            let temp_mem_taints: Vec<DataDomain<IntervalDomain>> =
                self.add_temporary_callee_saved_register_taints_to_mem_taints(pi_state, state);

            if state.address_points_to_taint(address.clone(), pi_state) {
                if let Some(standard_cconv) = self.project.get_standard_calling_convention() {
                    state.remove_callee_saved_taint_if_destination_parameter(
                        &address,
                        pi_state,
                        standard_cconv,
                    );
                }
                state.remove_mem_taint_at_target(&address);
                points_to_memory_taint = true;
            }

            temp_mem_taints
                .iter()
                .for_each(|addr| state.remove_mem_taint_at_target(addr));
        }

        points_to_memory_taint
    }

    /// Takes taints of callee saved registers and adds them temporarily to the corresponding memory
    /// taints if possible.
    pub fn add_temporary_callee_saved_register_taints_to_mem_taints(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State,
    ) -> Vec<DataDomain<IntervalDomain>> {
        let mut temp_mem_taints: Vec<DataDomain<IntervalDomain>> = Vec::new();
        if let Some(standard_cconv) = self.project.get_standard_calling_convention() {
            for (var, _) in state
                .get_callee_saved_register_taints(standard_cconv)
                .iter()
            {
                let address = pi_state.eval(&Expression::Var(var.clone()));
                if !state.address_points_to_taint(address.clone(), pi_state) {
                    temp_mem_taints.push(address.clone());
                    state.save_taint_to_memory(&address, Taint::Tainted(var.size));
                }
            }
        }

        temp_mem_taints
    }

    /// Checks whether the current def term is the last def term
    /// of its corresponding block and if so, returns the node index of the BlkStart node.
    pub fn get_blk_start_node_if_last_def(
        &self,
        state: &State,
        def: &Term<Def>,
    ) -> Option<NodeIndex> {
        if let Some(sub) = state.get_current_sub() {
            if let Some(node) = self
                .block_maps
                .block_start_last_def_map
                .get(&(def.tid.clone(), sub.tid.clone()))
            {
                return Some(*node);
            }
        } else {
            panic!("Missing current Sub.");
        }

        None
    }

    /// Creates a map from def terms to their corresponding pointer inference states
    /// by taking the pointer inference state of the BlkStart node and updating it
    /// for each def term in the block.
    pub fn create_pi_def_map(
        &self,
        block_start_node: NodeIndex,
    ) -> Option<HashMap<Tid, PointerInferenceState>> {
        if let Some(block_node) = self.get_pi_graph().node_weight(block_start_node) {
            if let Some(pi_value) = self
                .pointer_inference_results
                .get_node_value(block_start_node)
            {
                let mut pi_def_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

                let pi_context = self.pointer_inference_results.get_context();
                let mut new_pi_state = Some(pi_value.unwrap_value().clone());

                for def in block_node.get_block().term.defs.iter() {
                    // Add the pi state to the map that is available after the def was executed
                    // If no state is available after the update_def() call, none is added
                    if new_pi_state.is_none() {
                        break;
                    }
                    new_pi_state = pi_context.update_def(&new_pi_state.unwrap(), def);
                    if let Some(new_state) = new_pi_state.clone() {
                        pi_def_map.insert(def.tid.clone(), new_state);
                    }
                }

                return Some(pi_def_map);
            }
        } else {
            panic!("Unexpected node index for BlkStart Node.");
        }

        None
    }

    /// Handles assignment and load definition updates
    pub fn handle_assign_and_load(
        &self,
        state: State,
        def: &Term<Def>,
        var: &Variable,
        input: &Expression,
    ) -> State {
        let mut new_state = state;
        if let Some(taint) = new_state.get_register_taint(var) {
            if taint.is_tainted() {
                new_state.set_expression_taint_and_store_constants(
                    &def.tid,
                    var,
                    input,
                    &self.project.stack_pointer_register,
                    self.runtime_memory_image,
                )
            }
        }

        new_state
    }

    /// Gets the BlkEnd node of an external function call
    pub fn get_source_node(&self, state: &State, call_source: &Tid) -> NodeIndex {
        let blk_end_node_id = self.block_maps.jmp_to_blk_end_node_map.get(&(
            call_source.clone(),
            state.get_current_sub().as_ref().unwrap().tid.clone(),
        ));

        if let Some(blk_end_node) = blk_end_node_id {
            *blk_end_node
        } else {
            panic!("Malformed Control Flow Graph.");
        }
    }

    /// Updates the target state at the callsite by removing non parameter register taints
    /// and by merging callee saved register taints from the return state if available
    pub fn update_target_state_for_callsite(
        &self,
        return_state: Option<&State>,
        target_state: Option<&State>,
        caller_sub: &Term<Sub>,
    ) -> Option<State> {
        if let Some(target) = target_state {
            let mut new_state = target.clone();
            new_state.remove_non_parameter_taints_for_generic_function(self.project);
            new_state.set_current_sub(caller_sub);
            if let Some(return_) = return_state {
                new_state.merge_callee_saved_taints_from_return_state(
                    return_,
                    self.project.get_standard_calling_convention(),
                );
            }

            return Some(new_state);
        }

        None
    }
}

impl<'a> crate::analysis::backward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    /// Get the underlying graph of the fixpoint computation
    fn get_graph(&self) -> &Graph<'a> {
        &self.graph
    }

    /// Merge two states
    fn merge(&self, state1: &State, state2: &State) -> State {
        state1.merge(state2)
    }

    /// Updates State according to side effects of the definition
    fn update_def(&self, state: &State, def: &Term<Def>) -> Option<State> {
        if state.is_empty() {
            // Without taint there is nothing to propagate.
            return None;
        }
        let mut new_state = state.clone();
        // Check whether the def is the last def of a block and if so, create the
        // Def Pi Map
        if let Some(blk_start_node) = self.get_blk_start_node_if_last_def(&new_state, def) {
            new_state.set_pi_def_map(self.create_pi_def_map(blk_start_node));
        }

        match &def.term {
            Def::Assign { var, value: input }
            | Def::Load {
                var,
                address: input,
            } => new_state = self.handle_assign_and_load(new_state, def, var, input),
            Def::Store { address, value } => new_state.taint_value_to_be_stored(
                &def.tid,
                address,
                value,
                &self.project.stack_pointer_register,
                self.runtime_memory_image,
            ),
        }

        // Check whether the current def term is the first of the block and if so, remove
        // the pi_def_map for the current state to save memory
        if self
            .block_maps
            .block_first_def_set
            .get(&(
                def.tid.clone(),
                new_state.get_current_sub().as_ref().unwrap().tid.clone(),
            ))
            .is_some()
        {
            new_state.set_pi_def_map(None);
        }

        Some(new_state)
    }

    /// Either returns a copy of the input state when there is no conditional
    /// Or merges both incoming states from the branch and conditional branch
    fn update_jumpsite(
        &self,
        state_after_jump: &State,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _jumpsite: &Term<Blk>,
    ) -> Option<State> {
        Some(state_after_jump.clone())
    }

    /// The specific execution is dependent on the existence of a return and target state
    /// If there is no return state and the taint source is not in the callee, none is returned.
    /// If there is no return state and the taint source is in the callee, the target state is copied.
    /// If there is a return state and no target state, non callee saved registers are removed and the
    /// updated return state is let through.
    /// If there is a return state and a target state, non parameter taints are removed from the target state
    /// and the remaining taints plus the callee saved taints from the return state are combined in a new state
    fn update_callsite(
        &self,
        target_state: Option<&State>,
        return_state: Option<&State>,
        caller_sub: &Term<Sub>,
        _call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<State> {
        // Return state is present
        if let Some(return_) = return_state {
            // Update the target state if there is one. Otherwise clone the return state and
            // remove all non callee saved register taints
            let new_state =
                self.update_target_state_for_callsite(return_state, target_state, caller_sub);
            if new_state.is_none() {
                let mut new_state = return_.clone();
                if let Some(calling_conv) = self.project.get_standard_calling_convention() {
                    new_state.remove_non_callee_saved_taint(calling_conv);
                }

                return Some(new_state);
            }

            return new_state;
        // No return state: check for taint source
        } else {
            // If the called subroutine contains the taint source, update the target state if there is one.
            // Otherwise return None.
            if let Some(source_sub) = self.taint_source_sub {
                if source_sub.tid == caller_sub.tid {
                    return self.update_target_state_for_callsite(
                        return_state,
                        target_state,
                        caller_sub,
                    );
                }
            }
        }

        None
    }

    /// Simply sends a copy of the state after the call return to the callsite
    /// Will be used at the callsite to restore non-volatile registers
    fn split_call_stub(&self, combined_state: &State) -> Option<State> {
        Some(combined_state.clone())
    }

    /// Removes all register taints except for possible return register taints
    fn split_return_stub(
        &self,
        combined_state: &State,
        returned_from_sub: &Term<Sub>,
    ) -> Option<State> {
        let mut new_state = combined_state.clone();
        if let Some(calling_conv) = self.project.get_standard_calling_convention() {
            let return_registers: HashSet<String> =
                calling_conv.return_register.iter().cloned().collect();
            new_state.remove_all_except_return_register_taints(return_registers);
        }

        new_state.set_current_sub(returned_from_sub);

        Some(new_state)
    }

    /// Check whether the extern call is direct and if so, taint the extern symbol parameters and
    /// remove non callee saved registers.
    fn update_call_stub(&self, state_after_call: &State, call: &Term<Jmp>) -> Option<State> {
        if state_after_call.is_empty() {
            return None;
        }
        let mut new_state = state_after_call.clone();
        match &call.term {
            Jmp::Call { target, .. } => {
                let source_node = self.get_source_node(&new_state, &call.tid);
                if let Some(extern_symbol) = self.symbol_maps.extern_symbol_map.get(target) {
                    new_state = self.taint_generic_extern_symbol_parameters(
                        &new_state,
                        extern_symbol,
                        source_node,
                    )
                } else {
                    panic!("Extern symbol not found.");
                }
            }
            _ => panic!("Malformed control flow graph encountered."),
        }

        Some(new_state)
    }

    /// Just returns a copy of the input state.
    fn specialize_conditional(
        &self,
        state: &State,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<State> {
        Some(state.clone())
    }
}

#[cfg(test)]
mod tests;
