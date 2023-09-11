use super::{state::State, InitializationStatus};
use crate::abstract_domain::{DataDomain, SizedDomain, TryToBitvec};
use crate::analysis::pointer_inference::{PointerInference, ValueDomain};
use crate::analysis::{
    function_signature::FunctionSignature, graph::Graph, vsa_results::VsaResult,
};
use crate::intermediate_representation::*;
use crate::prelude::AnalysisResults;
use std::collections::BTreeMap;

pub struct Context<'a> {
    graph: &'a Graph<'a>,
    pub pir: &'a PointerInference<'a>,
    pub function_signatures: &'a BTreeMap<Tid, FunctionSignature>,
    pub extern_symbol_whitelist: Vec<String>,
}

impl<'a> Context<'a> {
    /// Create a new context object for the given project and control flow graph.
    pub fn new<'b>(
        analysis_results: &'b AnalysisResults<'a>,
        extern_symbol_whitelist: Vec<String>,
    ) -> Context<'a>
    where
        'a: 'b,
    {
        Context {
            graph: analysis_results.control_flow_graph,
            pir: analysis_results.pointer_inference.unwrap(),
            function_signatures: analysis_results.function_signatures.unwrap(),
            extern_symbol_whitelist,
        }
    }

    /// Utilizes Pointer Inference for evaluating and returns all parameters of an `ExternSymbol`
    fn extract_parameters(
        &self,
        symbol: &ExternSymbol,
        call_tid: &Tid,
    ) -> Vec<Option<DataDomain<ValueDomain>>> {
        symbol
            .parameters
            .iter()
            .map(|param| self.pir.eval_parameter_arg_at_call(call_tid, param))
            .collect()
    }

    /// Models the effect of a `memset` call to the state.
    ///
    /// Note: Under approximation:
    /// Only if the parameters target and size can be uniquely derived, the initialization effect of memset
    /// is applied. The state's offset are set to `InitializationStatus::Init` as defined by the parameters.
    /// If an new memory object is introduced, it is added to the state with the initialization effect.
    fn handle_memset(
        &self,
        call_tid: &Tid,
        memset_symbol: &ExternSymbol,
        value: &State,
    ) -> Option<State> {
        let params = self.extract_parameters(memset_symbol, call_tid);
        if let Some(target) = &params[0] {
            if let Some(size) = &params[2] {
                if let Some((id, target_offset_interval)) = target.get_if_unique_target() {
                    if let Ok(target_offset) = target_offset_interval.try_to_offset() {
                        if let Some(size_interval) = size.get_if_absolute_value() {
                            if let Ok(size) = size_interval.try_to_offset() {
                                let mut new_state = value.clone();
                                if !new_state.tracked_objects.contains_key(id) {
                                    new_state.add_new_object(id.clone(), target.bytesize());
                                }
                                for i in target_offset..=(target_offset + size) {
                                    new_state.insert_single_offset(
                                        id,
                                        i,
                                        InitializationStatus::Init {
                                            addresses: [call_tid.clone()].into(),
                                        },
                                    );
                                }
                                return Some(new_state);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Models the effect of a `memcpy` call to the state.
    ///
    /// Note: Under approximation
    /// Only if all parameters can be derived uniquely derived, the effect of `memcpy` is applied.
    /// The `InitializationStatus` of the source offsets is copied, thus target offsets might be `InitializationStatus::Uninit`
    /// If an new memory object is introduced, it is added to the state completely uninitialized.
    fn handle_memcpy(
        &self,
        call_tid: &Tid,
        memcpy_symbol: &ExternSymbol,
        value: &State,
    ) -> Option<State> {
        let params = self.extract_parameters(memcpy_symbol, call_tid);
        if let Some(target) = &params[0] {
            if let Some((target_id, target_interval)) = target.get_if_unique_target() {
                if let Ok(target_offset) = target_interval.try_to_offset() {
                    if let Some(source) = &params[1] {
                        if let Some((source_id, source_interval)) = source.get_if_unique_target() {
                            if let Ok(source_offset) = source_interval.try_to_offset() {
                                if let Some(size) = &params[2] {
                                    if let Ok(size) = size.try_to_offset().map(|x| x as u64) {
                                        let mut state = value.clone();
                                        if !state.tracked_objects.contains_key(target_id) {
                                            state.add_new_object(
                                                target_id.clone(),
                                                target.bytesize(),
                                            )
                                        }
                                        if !state.tracked_objects.contains_key(source_id) {
                                            state.add_new_object(
                                                source_id.clone(),
                                                source.bytesize(),
                                            )
                                        }

                                        match state.copy_range_from_other_object(
                                            source_id,
                                            source_offset,
                                            target_id,
                                            target_offset,
                                            size,
                                        ) {
                                            Ok(_) => return Some(state),
                                            Err(_) => todo!(),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Removes all memory objects that are arguments to `free` from the state.
    ///
    /// This is not necessary for the algorithm and only an optimization, since new memory objects are added, if
    /// the Pointer Inference keeps track of them.
    fn handle_free(
        &self,
        call_tid: &Tid,
        free_symbol: &ExternSymbol,
        value: &State,
    ) -> Option<State> {
        let params = self.extract_parameters(free_symbol, call_tid);
        if let Some(arg) = &params[0] {
            if let Some((arg_id, _)) = arg.get_if_unique_target() {
                if value.tracked_objects.contains_key(arg_id) {
                    let mut state = value.clone();
                    state.tracked_objects.remove(arg_id);
                }
            }
        }
        None
    }
}

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = State;

    fn get_graph(&self) -> &crate::analysis::graph::Graph<'a> {
        self.graph
    }

    /// Merges the set of tracked memory objects and their statuses.
    ///
    /// Both sets are combined, but if the status of the same memory object is initialized
    /// and uninitialized, the status is set to `MaybeInit`. This function is the only source of
    /// `MaybeInit`.
    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        let mut merged = value1.clone();
        for (id, mem_region) in value2.tracked_objects.iter() {
            if let Some(merge_mem_region) = merged.tracked_objects.get_mut(id) {
                merge_mem_region.merge(mem_region);
            } else {
                merged
                    .tracked_objects
                    .insert(id.clone(), mem_region.clone());
            }
        }
        merged
    }

    /// Changes the `InitalizationStatus` of an `Uninit` memory object's offset to `Init`, if a `Store` instruction
    /// manipulates the memory object's offset.
    fn update_def(&self, value: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        if let Def::Store { .. } = &def.term {
            if let Some(data_domain) = self.pir.eval_address_at_def(&def.tid) {
                for (id, interval) in data_domain.get_relative_values().iter() {
                    if value.tracked_objects.contains_key(id) {
                        // We track this mem object
                        if let Ok(mem_offset) = interval.try_to_offset() {
                            if let Some(value_domain) = self.pir.eval_value_at_def(&def.tid) {
                                let mut updated = value.clone();

                                for value_offset in 0..value_domain.bytesize().into() {
                                    updated.merge_precise_single_offset(
                                        id,
                                        mem_offset + value_offset as i64,
                                        &InitializationStatus::Init {
                                            addresses: [def.tid.clone()].into(),
                                        },
                                    );
                                }
                                return Some(updated);
                            }
                        }
                    } else {
                        let mut update = value.clone();
                        update.add_new_object(id.clone(), data_domain.bytesize());
                        return self.update_def(&update, def);
                    }
                }
            }
        }

        Some(value.clone())
    }

    fn update_jump(
        &self,
        value: &Self::Value,
        _jump: &crate::intermediate_representation::Term<crate::intermediate_representation::Jmp>,
        _untaken_conditional: Option<
            &crate::intermediate_representation::Term<crate::intermediate_representation::Jmp>,
        >,
        _target: &crate::intermediate_representation::Term<crate::intermediate_representation::Blk>,
    ) -> Option<Self::Value> {
        Some(value.clone())
    }

    fn update_call(
        &self,
        _value: &Self::Value,
        _call: &crate::intermediate_representation::Term<crate::intermediate_representation::Jmp>,
        _target: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None
    }

    fn update_return(
        &self,
        _value: Option<&Self::Value>,
        _value_before_call: Option<&Self::Value>,
        _call_term: &crate::intermediate_representation::Term<
            crate::intermediate_representation::Jmp,
        >,
        _return_term: &crate::intermediate_representation::Term<
            crate::intermediate_representation::Jmp,
        >,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None
    }

    fn update_call_stub(
        &self,
        value: &Self::Value,
        call: &crate::intermediate_representation::Term<crate::intermediate_representation::Jmp>,
    ) -> Option<Self::Value> {
        if let Some(extern_symbol) = match &call.term {
            Jmp::Call { target, .. } => self
                .pir
                .get_context()
                .project
                .program
                .term
                .extern_symbols
                .get(target),
            _ => None,
        } {
            match extern_symbol.name.as_str() {
                "memset" => return self.handle_memset(&call.tid, extern_symbol, value),
                "memcpy" => return self.handle_memcpy(&call.tid, extern_symbol, value),
                "free" => return self.handle_free(&call.tid, extern_symbol, value),
                _ => {}
            }
        }

        Some(value.clone())
    }

    fn specialize_conditional(
        &self,
        value: &Self::Value,
        _condition: &crate::intermediate_representation::Expression,
        _block_before_condition: &crate::intermediate_representation::Term<
            crate::intermediate_representation::Blk,
        >,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(value.clone())
    }
}
