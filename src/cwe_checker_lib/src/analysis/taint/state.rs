//! Property space of a taint analysis.
//!
//! Instances of the [`State`] type represent the taint state of memory and
//! registers at a certain location in the program.

use crate::abstract_domain::AbstractLocation;
use crate::abstract_domain::{
    AbstractDomain, AbstractIdentifier, IntervalDomain, MemRegion, RegisterDomain, SizedDomain,
    TryToBitvec,
};
use crate::analysis::graph::NodeIndex;
use crate::analysis::pointer_inference::Data as PiData;
use crate::analysis::vsa_results::VsaResult;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::debug::ToJsonCompact;

use std::collections::BTreeMap;

use super::Taint;

mod memory_taint;
mod register_taint;
#[cfg(test)]
mod tests;

use memory_taint::MemoryTaint;
use register_taint::RegisterTaint;

/// The state object of the taint analysis representing all known tainted memory
/// and register values at a certain location within the program.
#[derive(Serialize, Deserialize, Debug, Eq, Clone)]
pub struct State {
    /// The set of currently tainted registers.
    register_taint: RegisterTaint,
    /// The Taint contained in memory objects
    memory_taint: MemoryTaint,
}

impl ToJsonCompact for State {
    fn to_json_compact(&self) -> serde_json::Value {
        let mut state_map = serde_json::Map::new();

        let register_taint = self
            .register_taint
            .iter()
            .map(|(reg, taint)| (reg.name.clone(), taint.to_json_compact()))
            .collect();
        let register_taint = serde_json::Value::Object(register_taint);

        let memory_taint = self
            .memory_taint
            .iter()
            .map(|(mem_id, mem_region)| (mem_id.to_string(), mem_region.to_json_compact()))
            .collect();
        let memory_taint = serde_json::Value::Object(memory_taint);

        state_map.insert("registers".into(), register_taint);
        state_map.insert("memory".into(), memory_taint);

        serde_json::Value::Object(state_map)
    }
}

impl PartialEq for State {
    /// Two states are equal if the same values are tainted in both states.
    fn eq(&self, other: &Self) -> bool {
        self.register_taint == other.register_taint && self.memory_taint == other.memory_taint
    }
}

impl AbstractDomain for State {
    /// Merge two states.
    ///
    /// Any value tainted in at least one input state is also tainted in the
    /// merged state.
    fn merge(&self, other: &Self) -> Self {
        let mut new_state = self.clone();

        new_state.merge_with(other);

        new_state
    }

    fn merge_with(&mut self, other: &Self) -> &mut Self {
        self.register_taint.merge_with(&other.register_taint);
        self.memory_taint.merge_with(&other.memory_taint);

        self
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Returns an empty state.
    pub fn new_empty() -> Self {
        Self {
            register_taint: RegisterTaint::new(),
            memory_taint: MemoryTaint::new(),
        }
    }

    /// Returns a state where only return values of the extern call are tainted.
    pub fn new_return(
        taint_source: &ExternSymbol,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        return_node: NodeIndex,
    ) -> Self {
        let mut state = Self {
            register_taint: RegisterTaint::new(),
            memory_taint: MemoryTaint::new(),
        };

        for return_arg in taint_source.return_values.iter() {
            match return_arg {
                Arg::Register { expr, .. } => {
                    for var in expr.input_vars() {
                        state
                            .register_taint
                            .insert(var.clone(), Taint::Tainted(var.size));
                    }
                }
                Arg::Stack { address, size, .. } => {
                    if let Some(address) = vsa_result.eval_at_node(return_node, address) {
                        state.save_taint_to_memory(&address, Taint::Tainted(*size));
                    }
                }
            }
        }

        state
    }

    /// Evaluate whether the result of the given expression is tainted in the
    /// current state.
    pub fn eval(&self, expression: &Expression) -> Taint {
        match expression {
            Expression::Const(_) => Taint::Top(expression.bytesize()),
            Expression::Var(var) => {
                if self.register_taint.get(var).is_some() {
                    Taint::Tainted(var.size)
                } else {
                    Taint::Top(var.size)
                }
            }
            Expression::BinOp { op, lhs, rhs } => {
                let lhs_taint = self.eval(lhs);
                let rhs_taint = self.eval(rhs);
                lhs_taint.bin_op(*op, &rhs_taint)
            }
            Expression::UnOp { op, arg } => self.eval(arg).un_op(*op),
            Expression::Unknown { size, .. } => Taint::Top(*size),
            Expression::Cast { op, size, arg } => self.eval(arg).cast(*op, *size),
            Expression::Subpiece {
                low_byte,
                size,
                arg,
            } => self.eval(arg).subpiece(*low_byte, *size),
        }
    }

    /// Returns the taint of the value at the given address (with the given
    /// size).
    ///
    /// If the address may point to more than one location, then the taint state
    /// of all possible locations is merged. Only exact locations are
    /// considered, all other locations are treated as untainted.
    pub fn load_taint_from_memory(&self, address: &PiData, size: ByteSize) -> Taint {
        address
            .get_relative_values()
            .iter()
            .filter_map(|(mem_id, offset)| {
                if let (Some(mem_region), Ok(position)) =
                    (self.memory_taint.get(mem_id), offset.try_to_bitvec())
                {
                    Some(mem_region.get(position.clone(), size))
                } else {
                    None
                }
            })
            .fold(Taint::Top(size), |acc, next| acc.merge(&next))
    }

    /// Mark the value at the given address with the given taint.
    ///
    /// If the address may point to more than one object, we merge the taint
    /// into all objects for which the corresponding offset is exact. Since we
    /// merge, this will never remove any taint.
    ///
    /// If the pointee object and offset are exactly known, we write the
    /// `taint` to the object at the given offset. This may remove taint.
    ///
    /// In all other cases we do nothing.
    pub fn save_taint_to_memory(&mut self, address: &PiData, taint: Taint) {
        if let Some((mem_id, offset)) = get_if_unique_target(address) {
            if let Ok(position) = offset.try_to_bitvec() {
                if let Some(mem_region) = self.memory_taint.get_mut(mem_id) {
                    mem_region.add(taint, position);
                } else {
                    let mut mem_region = MemRegion::new(address.bytesize());
                    mem_region.add(taint, position);
                    self.memory_taint.insert(mem_id.clone(), mem_region);
                }
            }
        } else {
            for (mem_id, offset) in address.get_relative_values() {
                if let Ok(position) = offset.try_to_bitvec() {
                    if let Some(mem_region) = self.memory_taint.get_mut(mem_id) {
                        let old_taint = mem_region.get(position.clone(), taint.bytesize());
                        mem_region.add(old_taint.merge(&taint), position.clone());
                    } else {
                        let mut mem_region = MemRegion::new(address.bytesize());
                        mem_region.add(taint, position.clone());
                        self.memory_taint.insert(mem_id.clone(), mem_region);
                    }
                }
            }
        }
    }

    /// Remove all knowledge about taints contained in memory objects.
    pub fn remove_all_memory_taints(&mut self) {
        self.memory_taint = MemoryTaint::new();
    }

    /// Set the taint of a register.
    pub fn set_register_taint(&mut self, register: &Variable, taint: Taint) {
        if taint.is_top() {
            self.register_taint.remove(register);
        } else {
            self.register_taint.insert(register.clone(), taint);
        }
    }

    /// Returns the taint state of the given register.
    pub fn get_register_taint(&self, register: &Variable) -> Taint {
        self.register_taint
            .get(register)
            .copied()
            .unwrap_or(Taint::Top(register.size))
    }

    /// Returns true if the memory object with the given ID contains a tainted
    /// value.
    pub fn check_mem_id_for_taint(&self, id: &AbstractIdentifier) -> bool {
        self.memory_taint
            .get(id)
            .is_some_and(|mem_object| mem_object.values().any(|elem| elem.is_tainted()))
    }

    /// Check if the given address points to tainted memory.
    ///
    /// Returns true iff the value at any of the exact memory locations that the
    /// pointer may point to is tainted.
    pub fn check_if_address_points_to_taint(&self, address: &PiData) -> bool {
        address
            .get_relative_values()
            .iter()
            .any(|(target, offset)| {
                if let (Some(mem_object), Ok(target_offset)) =
                    (self.memory_taint.get(target), offset.try_to_bitvec())
                {
                    mem_object
                        .get_unsized(target_offset.clone())
                        .is_some_and(|taint| taint.is_tainted())
                } else {
                    false
                }
            })
    }

    /// Check if any register in the given register list contains taint.
    ///
    /// If `POINTER_TAINT` is selected, pointers to tainted memory are
    /// considered to be tainted.
    ///
    /// Returns `true` if taint was found and `false` if no taint was found.
    fn check_register_list_for_taint<const POINTER_TAINT: bool>(
        &self,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        jmp_tid: &Tid,
        register_list: &[Variable],
    ) -> bool {
        register_list.iter().any(|register| {
            // Check whether a register contains taint.
            self.register_taint.get(register).is_some_and(|taint| { !taint.is_top()})
            // Check whether some memory object referenced by a register may
            // contain taint.
            || (
                POINTER_TAINT
                && vsa_result
                .eval_parameter_location_at_call(jmp_tid, &AbstractLocation::Register(register.clone()))
                .is_some_and(|register_value| self.check_if_address_points_to_taint(&register_value))
            )
        })
    }

    /// Check if a generic function call may contain tainted values in its
    /// arguments.
    ///
    /// If `POINTER_TAINT` is selected, pointers to tainted memory are
    /// considered to be tainted.
    ///
    /// Since we don't know the actual parameters of the call, we approximate
    /// the parameters with all parameter registers of the calling convention of
    /// the function or of the standard calling convention of the project.
    ///
    /// In case no standard calling convention is found. We assume everything
    /// may be parameters or referenced by parameters, i.e., we assume the
    /// parameters of the call are tainted iff there is taint in the state.
    pub fn check_generic_function_params_for_taint<const POINTER_TAINT: bool>(
        &self,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        call_tid: &Tid,
        project: &Project,
        calling_convention_hint: &Option<String>,
    ) -> bool {
        if let Some(calling_conv) = project.get_specific_calling_convention(calling_convention_hint)
        {
            let mut all_parameters = calling_conv.integer_parameter_register.clone();
            for float_param in calling_conv.float_parameter_register.iter() {
                for var in float_param.input_vars() {
                    all_parameters.push(var.clone());
                }
            }
            self.check_register_list_for_taint::<POINTER_TAINT>(
                vsa_result,
                call_tid,
                &all_parameters,
            )
        } else {
            !self.is_empty()
        }
    }

    /// Check if the return registers may contain tainted values.
    ///
    /// If `POINTER_TAINT` is selected, pointers to tainted memory are
    /// considered to be tainted.
    ///
    /// Since we don't know the actual return registers, we approximate them by
    /// all return registers of the calling convention of the function or of the
    /// standard calling convention of the project.
    ///
    /// If no standard calling convention is found, we assume that everything
    /// may be a return value or referenced by return values.
    pub fn check_return_values_for_taint<const POINTER_TAINT: bool>(
        &self,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        return_tid: &Tid,
        project: &Project,
        calling_convention_hint: &Option<String>,
    ) -> bool {
        if let Some(calling_conv) = project.get_specific_calling_convention(calling_convention_hint)
        {
            self.check_register_list_for_taint::<POINTER_TAINT>(
                vsa_result,
                return_tid,
                &calling_conv.integer_return_register[..],
            )
        } else {
            !self.is_empty()
        }
    }

    /// Remove the taint from all registers not contained in the callee-saved
    /// register list of the given calling convention.
    pub fn remove_non_callee_saved_taint(&mut self, calling_conv: &CallingConvention) {
        self.register_taint = self
            .register_taint
            .iter()
            .filter_map(|(register, taint)| {
                if calling_conv
                    .callee_saved_register
                    .iter()
                    .any(|callee_saved_reg| register == callee_saved_reg)
                {
                    Some((register.clone(), *taint))
                } else {
                    None
                }
            })
            .collect();
    }

    /// Check parameters of a call to an extern symbol for taint.
    ///
    /// If `POINTER_TAINT` is selected, we also return true if a pointer to
    /// tainted memory is passed as an argument.
    pub fn check_extern_parameters_for_taint<const POINTER_TAINT: bool>(
        &self,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        extern_symbol: &ExternSymbol,
        call_tid: &Tid,
    ) -> bool {
        extern_symbol.parameters.iter().any(|parameter| {
            match parameter {
                Arg::Register { expr, .. } => {
                    // Check for taint directly in value of parameter register.
                    self.eval(expr).is_tainted()
                    ||
                    // Check if value in parameter register points to taint.
                    (POINTER_TAINT && vsa_result.eval_at_jmp(call_tid, expr).is_some_and(|register_value| {
                        self.check_if_address_points_to_taint(&register_value)
                    }))
                }
                Arg::Stack { address, size, .. } => {
                    // Check for taint directly in the stack-based argument.
                    vsa_result.eval_at_jmp(call_tid, address).is_some_and(|address_value| {
                        self
                            .load_taint_from_memory(&address_value, *size)
                            .is_tainted()})
                    ||
                    // Check if stack-based argument points to taint.
                    (POINTER_TAINT && vsa_result.eval_parameter_arg_at_call(call_tid, parameter).is_some_and(|stack_value| {
                        self.check_if_address_points_to_taint(&stack_value)
                    }))
                },
            }
        })
    }

    /// Check whether `self` contains any taint at all.
    pub fn is_empty(&self) -> bool {
        !self.has_memory_taint() && !self.has_register_taint()
    }

    /// Check whether there are any tainted registers in the state.
    pub fn has_register_taint(&self) -> bool {
        self.register_taint
            .iter()
            .any(|(_, taint)| matches!(*taint, Taint::Tainted(_)))
    }

    /// Check whether there is any tainted memory in the state.
    pub fn has_memory_taint(&self) -> bool {
        // NOTE: `self.memory_taint.is_empty()` would be incorrect since we may
        // track memory objects that contain no taint, e.g., if we overwrite a
        // tainted memory location with an untainted value.
        self.memory_taint
            .iter()
            .flat_map(|(_, mem_region)| mem_region.iter())
            .any(|(_, taint)| taint.is_tainted())
    }

    /// Merges the given `other` state into this state with renaming of abstract
    /// identifiers.
    ///
    /// The set of valid abstract identfiers (aIDs) is local to a given
    /// function. When merging states across function boundaries it is necessary
    /// to map aIDs into the set of valid aIDs in the target context before
    /// performing the merging.
    ///
    /// This function assumes that the target context is the one of `self` and
    /// that `renaming_map` specifies how valid aIDs in the context of `other`
    /// correspond to the aIDs of this context.
    pub fn merge_with_renaming(
        &mut self,
        other: &Self,
        renaming_map: Option<&BTreeMap<AbstractIdentifier, PiData>>,
    ) {
        let Self {
            register_taint: other_register_taint,
            memory_taint: other_memory_taint,
        } = other;

        // Naive merging works for register taint.
        self.register_taint.merge_with(other_register_taint);

        let Some(renaming_map) = renaming_map else {
            // Without a renaming rule we can not do anything meaningful with
            // the memory objects of the other state, i.e., we are done here.
            return;
        };

        for (other_aid, other_memory_object) in other_memory_taint.iter() {
            let Some(value) = renaming_map.get(other_aid) else {
                // The pointer inference decided that this object is not
                // referenced in the context of `self`, so no need to merge it.
                continue;
            };
            // There is more information in `value` that we could base our
            // decision on; however,
            // - we decide to ignore whether the `value` may  be absolute in the
            //   context of `self`. This is not important for taint analyses.
            // - in cases where it may be some unknown base + offset it is still
            //   worth handling the bases that we know about.
            for (aid, offset_interval) in value.get_relative_values() {
                let Ok(offset) = offset_interval.try_to_offset() else {
                    // The offset of the old memory object into the new one is
                    // not known exactly. At this point we could merge the old
                    // object at every possible offset (sound) or not merge at
                    // all (unsound).
                    //
                    // Depending on the analysis it will lead to more FP
                    // (CWE252) or FN (CWE476); on the upside, we have to track
                    // less state and are faster.
                    continue;
                };

                // Starts tracking the object if it does not exist.
                self.memory_taint
                    .merge_memory_object_with_offset(aid, other_memory_object, offset);
            }
        }
    }

    /// Deconstructs a `State` into its register and memory taint maps.
    pub fn into_mem_reg_taint(self) -> (RegisterTaint, MemoryTaint) {
        (self.register_taint, self.memory_taint)
    }

    /// Constructs a `State` from register and memory taint maps.
    pub fn from_mem_reg_taint(register_taint: RegisterTaint, memory_taint: MemoryTaint) -> Self {
        Self {
            register_taint,
            memory_taint,
        }
    }
}

impl State {
    /// Get a more compact json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    #[allow(dead_code)]
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let register: Vec<(String, Value)> = self
            .register_taint
            .iter()
            .map(|(var, data)| (var.name.clone(), json!(format!("{data}"))))
            .collect();
        let mut memory = Vec::new();
        for (tid, mem_region) in self.memory_taint.iter() {
            let mut elements = Vec::new();
            for (offset, elem) in mem_region.iter() {
                elements.push((offset.to_string(), json!(elem.to_string())));
            }
            memory.push((format!("{tid}"), Value::Object(Map::from_iter(elements))));
        }
        let state_map = vec![
            (
                "register".to_string(),
                Value::Object(Map::from_iter(register)),
            ),
            ("memory".to_string(), Value::Object(Map::from_iter(memory))),
        ];

        Value::Object(Map::from_iter(state_map))
    }
}

/// Returns target ID and offset iff there is a single relative value.
///
/// In contrast to `DataDomain::get_if_unique_target` this function also
/// returns the pair when the `is_top` flag is set or the value may be absolute.
fn get_if_unique_target(address: &PiData) -> Option<(&AbstractIdentifier, &IntervalDomain)> {
    let relative_values = address.get_relative_values();

    if relative_values.len() == 1 {
        Some(relative_values.iter().next().unwrap())
    } else {
        None
    }
}
