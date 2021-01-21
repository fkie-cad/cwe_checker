use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    iter::FromIterator,
};

use petgraph::{graph::NodeIndex, visit::IntoNodeReferences};

use super::{state::State, taint::Taint, CWE_MODULE};
use crate::{
    abstract_domain::AbstractDomain,
    analysis::{
        forward_interprocedural_fixpoint::Context as PiContext,
        graph::{Graph, Node},
        interprocedural_fixpoint_generic::NodeValue,
        pointer_inference::PointerInference as PointerInferenceComputation,
        pointer_inference::State as PointerInferenceState,
    },
    bil::Bitvector,
    intermediate_representation::*,
    utils::log::CweWarning,
};

#[derive(Clone)]
pub struct Context<'a> {
    /// A pointer to the corresponding project struct.
    project: &'a Project,
    /// The reversed pointer inference graph
    graph: Graph<'a>,
    /// A pointer to the results of the pointer inference analysis.
    /// They are used to determine the targets of pointers to memory,
    /// which in turn is used to keep track of taint on the stack or on the heap.
    pub pointer_inference_results: &'a PointerInferenceComputation<'a>,
    /// A map to get the node index of the `BlkStart` node containing a given [`Def`] as the last `Def` of the block.
    /// The keys are of the form `(Def-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    block_start_node_map: Arc<HashMap<(Tid, Tid), NodeIndex>>,
    /// Maps the TID of an extern symbol to the extern symbol struct.
    extern_symbol_map: Arc<HashMap<Tid, &'a ExternSymbol>>,
    /// Maps the TID of an extern string related symbol to the corresponding extern symbol struct.
    string_symbol_map: Arc<HashMap<Tid, &'a ExternSymbol>>,
    /// A map to get the node index of the `BlkEnd` node containing a given [`Jmp`].
    /// The keys are of the form `(Jmp-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    jmp_to_blk_end_node_map: Arc<HashMap<(Tid, Tid), NodeIndex>>,
    /// The call whose parameter values are the sources for taint for the analysis.
    pub taint_source: Option<&'a Term<Jmp>>,
    /// The name of the function, whose parameter values are the taint sources.
    pub taint_source_name: Option<String>,
    /// The current subfunction.
    ///Since the analysis is intraprocedural,
    ///all nodes with state during the fixpoint algorithm should belong to this function.
    current_sub: Option<&'a Term<Sub>>,
    /// A channel where found CWE hits can be sent to.
    cwe_collector: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> Context<'a> {
    pub fn new(
        project: &'a Project,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        string_symbols: HashMap<Tid, &'a ExternSymbol>,
        cwe_collector: crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        let mut block_start_node_map = HashMap::new();
        let mut extern_symbol_map = HashMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }
        let mut jmp_to_blk_end_node_map = HashMap::new();
        let graph = pointer_inference_results.get_graph();
        for (node_id, node) in graph.node_references() {
            match node {
                Node::BlkStart(block, sub) => match block.term.defs.len() {
                    0 => (),
                    num_of_defs => {
                        let last_def = block.term.defs.get(num_of_defs - 1).unwrap();
                        block_start_node_map
                            .insert((last_def.tid.clone(), sub.tid.clone()), node_id);
                    }
                },
                Node::BlkEnd(block, sub) => {
                    for jmp in block.term.jmps.iter() {
                        jmp_to_blk_end_node_map.insert((jmp.tid.clone(), sub.tid.clone()), node_id);
                    }
                }
                _ => (),
            }
        }
        let mut cwe_78_graph = graph.clone();
        cwe_78_graph.reverse();

        Context {
            project,
            graph: cwe_78_graph,
            pointer_inference_results,
            block_start_node_map: Arc::new(block_start_node_map),
            extern_symbol_map: Arc::new(extern_symbol_map),
            string_symbol_map: Arc::new(string_symbols),
            jmp_to_blk_end_node_map: Arc::new(jmp_to_blk_end_node_map),
            taint_source: None,
            taint_source_name: None,
            current_sub: None,
            cwe_collector,
        }
    }

    /// Generates the CWE Warning for the CWE 78 check
    pub fn generate_cwe_warning(
        &self,
        sub_name: &String,
    ) {
        let source = self.taint_source.unwrap();
        let name = self.taint_source_name.clone().unwrap();
        let description: String = format!(
            "(Potential OS Command Injection) {} ({}) -> {}",
            sub_name, source.tid.address, name
        );
        let cwe_warning = CweWarning::new(
       String::from(CWE_MODULE.name),
    String::from(CWE_MODULE.version),
            description,
        )
        .addresses(vec![source.tid.address.clone()])
        .tids(vec![format!("{}", source.tid)])
        .symbols(vec![String::from(sub_name)])
        .other(vec![vec![
            String::from("OS Command Injection"),
            String::from(name),
        ]]);
        let _ = self.cwe_collector.send(cwe_warning);
    }

    /// Set the taint source and the current function for the analysis.
    pub fn set_taint_source(&mut self, taint_source: &'a Term<Jmp>, current_sub: &'a Term<Sub>) {
        let taint_source_name = match &taint_source.term {
            Jmp::Call { target, .. } => self
                .project
                .program
                .term
                .extern_symbols
                .iter()
                .find_map(|symb| {
                    if symb.tid == *target {
                        Some(symb.name.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string()),
            _ => "Unknown".to_string(),
        };
        self.taint_source = Some(taint_source);
        self.taint_source_name = Some(taint_source_name);
        self.current_sub = Some(current_sub);
    }

    /// Returns the pointer inference graph
    pub fn get_pi_graph(&self) -> &Graph<'a> {
        self.pointer_inference_results.get_graph()
    }

    /// This function taints the registers and stack positions of the parameter pointers for string functions
    /// such as sprintf, snprintf, etc.
    /// The size parameter is ignored if available (e.g. snprintf, strncat etc.)
    pub fn taint_string_function_parameters(
        &self,
        state: &State,
        string_symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();

        if let Some(NodeValue::Value(pi_state)) = self
            .pointer_inference_results
            .get_node_value(call_source_node)
        {
            let mut relevant_fuction_call = false;
            for parameter in string_symbol.parameters.iter() {
                if let Ok(address) =
                    pi_state.eval_parameter_arg(parameter, &self.project.stack_pointer_register)
                {
                    // Check whether the parameter points to a tainted memory target
                    // Since the first parameter of these string functions is also the return parameter,
                    // this will serve as an indicator whether the function call is relevant to the taint analysis.
                    if state.check_if_address_points_to_taint(address.clone(), pi_state) == true {
                        new_state.remove_mem_taint_at_target(&address);
                        relevant_fuction_call = true;
                    }
                    if relevant_fuction_call {
                        match parameter {
                            Arg::Register(var) => {
                                new_state.set_register_taint(var, Taint::Tainted(var.size))
                            }
                            Arg::Stack { size, .. } => {
                                new_state.save_taint_to_memory(&address, Taint::Tainted(*size))
                            }
                        }
                    }
                }
            }
        }
        new_state
    }

    /// This function taints the registers and stack positions of the parameter pointers of external functions
    /// If the function is one of the specified string functions, the processing of the call is transferred to
    /// the string function processor
    pub fn taint_generic_function_parameters_and_remove_non_callee_saved(
        &self,
        state: &State,
        symbol: &ExternSymbol,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();
        // Check if the extern symbol is a string symbol, since the return register is not tainted for these.
        // Instead, is has to be checked whether the first function parameter points to a tainted memory address
        if self.string_symbol_map.get(&symbol.tid).is_some() {
            new_state.remove_non_callee_saved_taint(symbol.get_calling_convention(self.project));
            new_state = self.taint_string_function_parameters(&new_state, symbol, call_source_node);
        } else {
            // Check whether the return register is tainted before the call
            // If so, taint the parameter registers and memory addresses of possible stack parameters
            let return_registers = symbol
                .return_values
                .iter()
                .filter_map(|ret| match ret {
                    Arg::Register(var) => Some(var.name.clone()),
                    _ => None,
                })
                .collect::<Vec<String>>();
            if new_state.check_return_registers_for_taint(return_registers) {
                new_state
                    .remove_non_callee_saved_taint(symbol.get_calling_convention(self.project));
                if symbol.name == "scanf" {
                    self.generate_cwe_warning(&self.current_sub.unwrap().term.name);
                }
                return self.taint_parameters(
                    &new_state,
                    symbol.parameters.clone(),
                    call_source_node,
                );
            }
        }

        new_state
    }

    pub fn taint_stack_parameters(
        &self,
        state: State,
        call_source_node: NodeIndex,
        offset: i64,
        size: ByteSize,
    ) -> State {
        let mut new_state = state.clone();
        if let Some(NodeValue::Value(pi_state)) = self
            .pointer_inference_results
            .get_node_value(call_source_node)
        {
            let address_exp = Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(self.project.stack_pointer_register.clone())),
                rhs: Box::new(Expression::Const(
                    Bitvector::from_i64(offset)
                        .into_truncate(apint::BitWidth::from(
                            self.project.stack_pointer_register.size,
                        ))
                        .unwrap(),
                )),
            };
            if let Ok(address) = pi_state.eval(&address_exp) {
                new_state.save_taint_to_memory(&address, Taint::Tainted(size));
            }
        }
        new_state
    }

    // Iterates over the given parameters of a function and returns an updated state
    pub fn taint_parameters(
        &self,
        state: &State,
        parameters: Vec<Arg>,
        call_source_node: NodeIndex,
    ) -> State {
        let mut new_state = state.clone();
        for parameter in parameters {
            match parameter {
                Arg::Register(param) => {
                    new_state.set_register_taint(&param, Taint::Tainted(param.size))
                }
                Arg::Stack { offset, size } => {
                    new_state = self.taint_stack_parameters(
                        new_state.clone(),
                        call_source_node,
                        offset,
                        size,
                    );
                }
            }
        }

        new_state
    }

    /// Checks whether the current def term is the last def term
    /// of its corresponding block and if so, returns the block term and correspondoing
    pub fn get_blk_start_node_if_last_def(&self, def: &Term<Def>) -> Option<NodeIndex> {
        if let Some(sub) = self.current_sub {
            if let Some(node) = self
                .block_start_node_map
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
    /// for each def term in the block
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
        let mut new_state = state.clone();
        if let Some(taint) = new_state.get_register_taint(var) {
            match taint {
                Taint::Tainted(_) => new_state.set_expression_taint_and_store_constants(
                    &def.tid,
                    var,
                    input,
                    &self.project.stack_pointer_register,
                ),
                _ => (),
            }
        }

        new_state
    }

    /// Handles store definition updates
    pub fn handle_store(
        &self,
        state: State,
        def: &Term<Def>,
        address: &Expression,
        value: &Expression,
    ) -> State {
        let mut new_state = state.clone();
        let target = match address {
            Expression::Var(ram_target) => ram_target,
            Expression::Subpiece { arg, .. } => {
                let argument: &Expression = arg;
                match argument {
                    Expression::Var(ram_target) => ram_target,
                    _ => panic!("Unexpected target format for Store instruction!"),
                }
            }
            _ => panic!("Unexpected target format for Store instruction!"),
        };
        new_state.taint_value_to_be_stored(&def.tid, target, value);

        new_state
    }

    /// Gets the BlkEnd node of an external function call
    pub fn get_source_node(&self, call_source: &Tid) -> NodeIndex {
        let blk_end_node_id = self
            .jmp_to_blk_end_node_map
            .get(&(call_source.clone(), self.current_sub.unwrap().tid.clone()));

        if let Some(blk_end_node) = blk_end_node_id {
            return blk_end_node.clone();
        } else {
            panic!("Malformed Control Flow Graph.");
        }
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
        if let Some(blk_start_node) = self.get_blk_start_node_if_last_def(def) {
            new_state.set_pi_def_map(self.create_pi_def_map(blk_start_node));
        }

        match &def.term {
            Def::Assign { var, value: input }
            | Def::Load {
                var,
                address: input,
            } => new_state = self.handle_assign_and_load(new_state, def, var, input),
            Def::Store { address, value } => {
                new_state = self.handle_store(new_state, def, address, value)
            }
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

    fn update_callsite(
        &self,
        target_state: Option<&State>,
        return_state: Option<&State>,
        _call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<State> {
        if let Some(return_) = return_state {
            // If there is both a return and target state, first remove all non parameter
            // taints from the target state and merge in all callee saved register taints from
            // the return state. The new state will contain possible parameter taints, possible callee saved taints and
            // possible memory taints
            if let Some(target) = target_state {
                let mut new_state = target.clone();
                new_state.remove_non_parameter_taints_for_generic_function(self.project);
                if let Some(calling_conv) = self.project.get_standard_calling_convention() {
                    let callee_saved_registers: HashSet<String> =
                        HashSet::from_iter(calling_conv.callee_saved_register.iter().cloned());
                    for (variable, taint) in return_.get_register_taints() {
                        if callee_saved_registers.get(&variable.name).is_some() {
                            new_state.set_register_taint(variable, *taint);
                        }
                    }

                    return Some(new_state);
                }
            }
            // If there is no target state, try to get the standard calling convention of the called function
            // and remove all non callee saved registers taints from the state at the return side
            let mut new_state = return_.clone();
            if let Some(calling_conv) = self.project.get_standard_calling_convention() {
                new_state.remove_non_callee_saved_taint(calling_conv);
            }

            return Some(new_state);
        }

        // If there no return state, there will also be no target state and therefore None is returned
        None
    }

    /// Simply sends a copy of the state after the call return to the callsite
    /// Will be used at the callsite to restore non-volatile registers
    fn split_call_stub(&self, combined_state: &State) -> Option<State> {
        Some(combined_state.clone())
    }

    /// Removes all register taints except for possible return register taints
    fn split_return_stub(&self, combined_state: &State) -> Option<State> {
        let mut new_state = combined_state.clone();
        if let Some(calling_conv) = self.project.get_standard_calling_convention() {
            let return_registers: HashSet<String> =
                HashSet::from_iter(calling_conv.return_register.iter().cloned());

            new_state.remove_all_except_return_register_taints(return_registers);
        }
        Some(new_state)
    }

    /// Check whether the term is a direkt or indirekt call. If it is direct, check for the
    /// called symbol and update the taints accordingly
    /// If the call is indirect, get the standard calling convention, if available, and
    /// taint parameter if the return register was tainted and remove all non callee saved registers from the taint
    fn update_call_stub(&self, state_after_call: &State, call: &Term<Jmp>) -> Option<State> {
        if state_after_call.is_empty() {
            return None;
        }
        let mut new_state = state_after_call.clone();
        match &call.term {
            Jmp::Call { target, .. } => {
                let source_node = self.get_source_node(&call.tid);
                if let Some(extern_symbol) = self.extern_symbol_map.get(target) {
                    new_state = self.taint_generic_function_parameters_and_remove_non_callee_saved(
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
