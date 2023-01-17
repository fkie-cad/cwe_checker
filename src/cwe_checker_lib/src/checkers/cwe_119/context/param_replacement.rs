use super::Context;
use crate::abstract_domain::*;
use crate::analysis::pointer_inference::Data;
use crate::analysis::vsa_results::VsaResult;
use crate::intermediate_representation::*;
use crate::pipeline::AnalysisResults;
use std::collections::{BTreeMap, HashMap, HashSet};

impl<'a> Context<'a> {
    /// Merge all possible caller values for the given parameter ID.
    /// The absolute values also merged separately to prevent widening operations during the merge.
    fn substitute_param_values(
        &self,
        param_id: &AbstractIdentifier,
    ) -> (Option<IntervalDomain>, Data) {
        let mut merged_absolute_value: Option<IntervalDomain> = None;
        let mut merged_data: Option<Data> = None;
        let function_tid = param_id.get_tid();
        if let Some(callsites) = self.callee_to_callsites_map.get(function_tid) {
            for callsite in callsites {
                let param_id_at_callsite =
                    AbstractIdentifier::new(callsite.clone(), param_id.get_location().clone());
                let value_at_callsite = match self.param_replacement_map.get(&param_id_at_callsite)
                {
                    Some(val) => val,
                    None => continue,
                };
                merged_absolute_value = match (
                    &merged_absolute_value,
                    value_at_callsite.get_absolute_value(),
                ) {
                    (Some(val_left), Some(val_right)) => Some(val_left.signed_merge(val_right)),
                    (Some(val), None) | (None, Some(val)) => Some(val.clone()),
                    (None, None) => None,
                };
                merged_data = merged_data
                    .map(|val| val.merge(value_at_callsite))
                    .or_else(|| Some(value_at_callsite.clone()));
            }
        }
        let merged_data = merged_data.unwrap_or_else(|| Data::new_top(param_id.bytesize()));
        (merged_absolute_value, merged_data)
    }

    /// Recursively merge and insert all possible caller vallues for all parameter IDs contained in the given value.
    /// Absolute values are merged separately to prevent widening operations during the merge.
    ///
    /// Since recursive function calls could lead to infinite loops during the merge operation,
    /// each parameter ID is substituted at most once during the algorithm.
    /// This can lead to unresolved parameter IDs still contained in the final result,
    /// in some cases this can also happen without the presence of recursive function calls.
    pub fn recursively_substitute_param_values(&self, value: &Data) -> Data {
        let subs_list = &self.project.program.term.subs;
        let mut already_handled_ids = HashSet::new();
        let mut merged_absolute_value: Option<IntervalDomain> = value.get_absolute_value().cloned();
        let mut merged_data = value.clone();
        let mut has_stabilized = false;
        while !has_stabilized {
            has_stabilized = true;
            let mut replacement_map: BTreeMap<AbstractIdentifier, Data> = BTreeMap::new();
            for (id, offset) in merged_data.get_relative_values().clone() {
                if !already_handled_ids.insert(id.clone())
                    || !id.get_path_hints().is_empty()
                    || !subs_list.contains_key(id.get_tid())
                    || *id.get_location()
                        == AbstractLocation::Register(self.project.stack_pointer_register.clone())
                {
                    // ID was already present in `already_handled_ids` or it is not a parameter ID
                    replacement_map.insert(
                        id.clone(),
                        Data::from_target(id, Bitvector::zero(offset.bytesize().into()).into()),
                    );
                } else {
                    has_stabilized = false;
                    let (caller_absolute_value, caller_data) = self.substitute_param_values(&id);
                    replacement_map.insert(id, caller_data);
                    merged_absolute_value = match (
                        merged_absolute_value,
                        caller_absolute_value.map(|val| val + offset),
                    ) {
                        (Some(val_left), Some(val_right)) => {
                            Some(val_left.signed_merge(&val_right))
                        }
                        (Some(val), None) | (None, Some(val)) => Some(val.clone()),
                        (None, None) => None,
                    };
                }
            }
            merged_data.replace_all_ids(&replacement_map);
        }
        merged_data.set_absolute_value(merged_absolute_value);
        merged_data
    }

    /// Replace all parameter IDs in the given value.
    /// The replaced values are those of the parameters at the given call,
    /// i.e. the replacement is context-sensitive to a specific call.
    fn substitute_param_values_context_sensitive(
        &self,
        value: &Data,
        call_tid: &Tid,
        current_fn_tid: &Tid,
    ) -> Data {
        let mut replacement_map: BTreeMap<AbstractIdentifier, Data> = BTreeMap::new();
        for (id, offset) in value.get_relative_values().clone() {
            if id.get_tid() == current_fn_tid && id.get_path_hints().is_empty() {
                // Possible function param ID
                let param_id_at_callsite =
                    AbstractIdentifier::new(call_tid.clone(), id.get_location().clone());
                if let Some(value_at_callsite) =
                    self.param_replacement_map.get(&param_id_at_callsite)
                {
                    replacement_map.insert(id, value_at_callsite.clone());
                } // Else it is a pointer to the current stack frame, which is invalid in the caller.
            } else {
                // Not a function param.
                replacement_map.insert(
                    id.clone(),
                    Data::from_target(id, Bitvector::zero(offset.bytesize().into()).into()),
                );
            }
        }
        let mut result = value.clone();
        result.replace_all_ids(&replacement_map);
        result
    }

    /// Replace all parameter IDs in the given value using the given path hints
    /// to replace them with the corresponding values in the calling context of the path hints.
    pub fn recursively_substitute_param_values_context_sensitive(
        &self,
        value: &Data,
        current_fn_tid: &Tid,
        path_hints: &[Tid],
    ) -> Data {
        let mut substituted_value = value.clone();
        let mut current_fn_tid = current_fn_tid.clone();
        if path_hints.is_empty() {
            return substituted_value;
        }
        for call_tid in path_hints {
            substituted_value = self.substitute_param_values_context_sensitive(
                &substituted_value,
                call_tid,
                &current_fn_tid,
            );
            // Now set the new current_fn_tid to the TID of the caller function.
            current_fn_tid = self.call_to_caller_fn_map[call_tid].clone();
        }
        substituted_value
    }
}

/// Compute a mapping that maps each parameter of each call (given by an abstract identifier representing the parameter value at the callsite).
/// to its value at the callsite according to the pointer inference analysis.
pub fn compute_param_replacement_map(
    analysis_results: &AnalysisResults,
) -> HashMap<AbstractIdentifier, Data> {
    let mut param_replacement_map = HashMap::new();
    for sub in analysis_results.project.program.term.subs.values() {
        for blk in &sub.term.blocks {
            for jmp in &blk.term.jmps {
                match &jmp.term {
                    Jmp::Call { target, .. } => add_param_replacements_for_call(
                        analysis_results,
                        jmp,
                        target,
                        &mut param_replacement_map,
                    ),
                    Jmp::CallInd { .. } => (), // FIXME: indirect call targets not yet supported.
                    _ => (),
                }
            }
        }
    }
    param_replacement_map
}

/// For each parameter of the given call term map the abstract identifier representing the value of the parameter at the callsite
/// to its concrete value (in the context of the caller).
/// Add the mappings to the given `replacement_map`.
fn add_param_replacements_for_call(
    analysis_results: &AnalysisResults,
    call: &Term<Jmp>,
    callee_tid: &Tid,
    replacement_map: &mut HashMap<AbstractIdentifier, Data>,
) {
    let vsa_results = analysis_results.pointer_inference.unwrap();
    if let Some(fn_sig) = analysis_results
        .function_signatures
        .unwrap()
        .get(callee_tid)
    {
        for param_arg in fn_sig.parameters.keys() {
            if let Some(param_value) = vsa_results.eval_parameter_arg_at_call(&call.tid, param_arg)
            {
                let param_id = AbstractIdentifier::from_arg(&call.tid, param_arg);
                replacement_map.insert(param_id, param_value);
            }
        }
    } else if let Some(extern_symbol) = analysis_results
        .project
        .program
        .term
        .extern_symbols
        .get(callee_tid)
    {
        for param_arg in &extern_symbol.parameters {
            if let Some(param_value) = vsa_results.eval_parameter_arg_at_call(&call.tid, param_arg)
            {
                let param_id = AbstractIdentifier::from_arg(&call.tid, param_arg);
                replacement_map.insert(param_id, param_value);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_substitute_param_values_context_sensitive() {
        let mut context = Context::mock_x64();
        let param_id = AbstractIdentifier::mock("func", "RDI", 8);
        let callsite_id = AbstractIdentifier::mock("callsite_id", "RDI", 8);

        let recursive_param_id = AbstractIdentifier::mock("main", "RSI", 8);
        let recursive_callsite_id = AbstractIdentifier::mock("recursive_callsite_id", "RSI", 8);

        let param_value =
            Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(1).into());
        let recursive_param_value = Data::from(Bitvector::from_i64(41));
        let param_replacement_map = HashMap::from([
            (callsite_id, param_value.clone()),
            (recursive_callsite_id.clone(), recursive_param_value),
        ]);
        let callee_to_callsites_map = HashMap::from([
            (Tid::new("func"), HashSet::from([Tid::new("callsite_id")])),
            (
                Tid::new("main"),
                HashSet::from([Tid::new("recursive_callsite_id")]),
            ),
        ]);
        let call_to_caller_map = HashMap::from([
            (Tid::new("callsite_id"), Tid::new("main")),
            (
                Tid::new("recursive_callsite_id"),
                Tid::new("somer_other_fn_id"),
            ),
        ]);
        context.param_replacement_map = param_replacement_map;
        context.callee_to_callsites_map = callee_to_callsites_map;
        context.call_to_caller_fn_map = call_to_caller_map;
        // non-recursive substitution
        let result = context.substitute_param_values_context_sensitive(
            &Data::from_target(param_id.clone(), Bitvector::from_i64(5).into()),
            &Tid::new("callsite_id"),
            &Tid::new("func"),
        );
        assert_eq!(
            result,
            Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(6).into())
        );
        // recursive substitution
        let result = context.recursively_substitute_param_values_context_sensitive(
            &Data::from_target(param_id, Bitvector::from_i64(5).into()),
            &Tid::new("func"),
            &[Tid::new("callsite_id"), Tid::new("recursive_callsite_id")],
        );
        println!("{:#}", result.to_json_compact());
        assert_eq!(result, Bitvector::from_i64(47).into());
    }

    #[test]
    fn test_substitute_param_values() {
        let mut context = Context::mock_x64();
        let param_id = AbstractIdentifier::mock("func", "RDI", 8);
        let callsite_id = AbstractIdentifier::mock("callsite_id", "RDI", 8);

        let recursive_param_id = AbstractIdentifier::mock("main", "RSI", 8);
        let recursive_callsite_id = AbstractIdentifier::mock("recursive_callsite_id", "RSI", 8);

        let param_value =
            Data::from_target(recursive_param_id.clone(), Bitvector::from_i64(1).into());
        let recursive_param_value = Data::from(Bitvector::from_i64(39));
        let param_replacement_map = HashMap::from([
            (callsite_id, param_value.clone()),
            (recursive_callsite_id.clone(), recursive_param_value),
        ]);
        let callee_to_callsites_map = HashMap::from([
            (Tid::new("func"), HashSet::from([Tid::new("callsite_id")])),
            (
                Tid::new("main"),
                HashSet::from([Tid::new("recursive_callsite_id")]),
            ),
        ]);
        context.param_replacement_map = param_replacement_map;
        context.callee_to_callsites_map = callee_to_callsites_map;
        // non-recursive substitution
        let (result_absolute, result) = context.substitute_param_values(&param_id);
        assert!(result_absolute.is_none());
        assert_eq!(result, param_value);
        // recursive substitution
        let result = context.recursively_substitute_param_values(&Data::from_target(
            param_id,
            Bitvector::from_i64(5).into(),
        ));
        assert_eq!(result, Bitvector::from_i64(45).into());
    }
}
