//! This module contains the Context Object for the String Abstraction.
//! It holds all necessary information that stays unchanged during the analysis.

use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use petgraph::{graph::NodeIndex, visit::IntoNodeReferences};

use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop},
    analysis::{
        forward_interprocedural_fixpoint::Context as _, graph::Node,
        interprocedural_fixpoint_generic::NodeValue,
        pointer_inference::PointerInference as PointerInferenceComputation,
        pointer_inference::State as PointerInferenceState,
    },
    intermediate_representation::{Def, ExternSymbol, Project, Term, Tid},
    utils::binary::RuntimeMemoryImage,
};

use super::{state::State, Config};

pub mod symbol_calls;
mod trait_impls;

/// Contains all context information needed for the string abstract fixpoint computation.
///
/// The struct also implements the `interprocedural_fixpoint::Context` trait to enable the fixpoint computation.
pub struct Context<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> {
    /// A reference to the `Project` object representing the binary
    pub project: &'a Project,
    /// The runtime memory image for reading global read-only variables.
    /// Note that values of writeable global memory segments are not tracked.
    pub runtime_memory_image: &'a RuntimeMemoryImage,
    /// A pointer to the results of the pointer inference analysis.
    /// They are used to determine the targets of pointers to memory,
    /// which in turn is used to keep track of taint on the stack or on the heap.
    pub pointer_inference_results: &'a PointerInferenceComputation<'a>,
    /// Maps the TIDs of functions that shall be treated as string extern symbols to the `ExternSymbol` object representing it.
    pub string_symbol_map: HashMap<Tid, &'a ExternSymbol>,
    /// Maps the TIDs of functions that shall be treated as general extern symbols to the `ExternSymbol` object representing it.
    pub extern_symbol_map: HashMap<Tid, &'a ExternSymbol>,
    /// Maps string symbols to their corresponding format string parameter index.
    pub format_string_index_map: HashMap<String, usize>,
    /// A map to get the node index of the `BlkStart` node containing a given [`Def`] as the first `Def` of the block.
    /// The keys are of the form `(Def-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    pub block_start_node_map: HashMap<(Tid, Tid), NodeIndex>,
    /// A set containing a given [`Def`](crate::intermediate_representation::Def) as the first `Def` of the block.
    /// The keys are of the form `(Def-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    pub block_first_def_set: HashSet<(Tid, Tid)>,
    /// A map to get the node index of the `BlkEnd` node containing a given [`Jmp`](crate::intermediate_representation::Jmp).
    /// The keys are of the form `(Jmp-TID, Current-Sub-TID)`
    /// to distinguish the nodes for blocks contained in more than one function.
    pub jmp_to_blk_end_node_map: HashMap<(Tid, Tid), NodeIndex>,
    _phantom_string_domain: PhantomData<T>,
}
impl<'a, T: AbstractDomain + HasTop + Eq + From<String> + DomainInsertion> Context<'a, T> {
    /// Create a new context object for a given project.
    pub fn new(
        project: &'a Project,
        runtime_memory_image: &'a RuntimeMemoryImage,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
        config: Config,
    ) -> Context<'a, T> {
        let string_symbol_map =
            crate::utils::symbol_utils::get_symbol_map(project, &config.string_symbols[..]);
        let mut extern_symbol_map = HashMap::new();
        for (tid, symbol) in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(tid.clone(), symbol);
        }

        let mut block_start_node_map: HashMap<(Tid, Tid), NodeIndex> = HashMap::new();
        let mut block_first_def_set = HashSet::new();
        let mut jmp_to_blk_end_node_map = HashMap::new();
        for (node_id, node) in pointer_inference_results.get_graph().node_references() {
            match node {
                Node::BlkStart(block, sub) => {
                    if let Some(def) = block.term.defs.get(0) {
                        block_start_node_map.insert((def.tid.clone(), sub.tid.clone()), node_id);
                        block_first_def_set.insert((def.tid.clone(), sub.tid.clone()));
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

        Context {
            project,
            runtime_memory_image,
            pointer_inference_results,
            format_string_index_map: config.format_string_index.into_iter().collect(),
            string_symbol_map,
            extern_symbol_map,
            block_start_node_map,
            block_first_def_set,
            jmp_to_blk_end_node_map,
            _phantom_string_domain: PhantomData,
        }
    }

    /// Get the current pointer inference state (if one can be found) for the given state.
    fn get_current_pointer_inference_state(
        &self,
        state: &State<T>,
        tid: &Tid,
    ) -> Option<PointerInferenceState> {
        if let Some(pi_state) = state.get_pointer_inference_state() {
            Some(pi_state.clone())
        } else if let Some(node_id) = self
            .block_start_node_map
            .get(&(tid.clone(), state.get_current_sub().unwrap().tid.clone()))
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
    fn update_pointer_inference_state(&self, state: &mut State<T>, def: &Term<Def>) {
        if let Some(pi_state) = self.get_current_pointer_inference_state(state, &def.tid) {
            let pi_context = self.pointer_inference_results.get_context();
            let new_pi_state = pi_context.update_def(&pi_state, def);
            state.set_pointer_inference_state(new_pi_state);
        }
    }
}

#[cfg(test)]
mod tests;
