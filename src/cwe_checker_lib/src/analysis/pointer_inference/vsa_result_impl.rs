use super::*;
use crate::analysis::graph::NodeIndex;
use crate::{abstract_domain::AbstractLocation, analysis::vsa_results::VsaResult};

/// Implementation of the [`VsaResult`] trait for providing other analyses with an easy-to-use interface
/// to use the value set and points-to analysis results of the pointer inference.
impl<'a> VsaResult for PointerInference<'a> {
    type ValueDomain = Data;

    /// Return the value of the address at the given read or store instruction.
    fn eval_address_at_def(&self, def_tid: &Tid) -> Option<Data> {
        self.addresses_at_defs.get(def_tid).cloned()
    }

    /// Return the assigned value for store or assignment instructions or the value read for load instructions.
    fn eval_value_at_def(&self, def_tid: &Tid) -> Option<Data> {
        self.values_at_defs.get(def_tid).cloned()
    }

    /// Evaluate the value of the given expression at the given jump instruction.
    fn eval_at_jmp(&self, jmp_tid: &Tid, expression: &Expression) -> Option<Data> {
        let state = self.states_at_tids.get(jmp_tid)?;
        Some(state.eval(expression))
    }

    /// Evaluate the value of the given parameter at the given jump instruction.
    fn eval_parameter_arg_at_call(&self, jmp_tid: &Tid, parameter: &Arg) -> Option<Data> {
        let state = self.states_at_tids.get(jmp_tid)?;
        let context = self.computation.get_context().get_context();
        state
            .eval_parameter_arg(parameter, &context.project.runtime_memory_image)
            .ok()
    }

    /// Evaluate the value of the given parameter at the given jump instruction.
    fn eval_parameter_location_at_call(
        &self,
        jmp_tid: &Tid,
        parameter: &AbstractLocation,
    ) -> Option<Data> {
        let state = self.states_at_tids.get(jmp_tid)?;
        let context = self.computation.get_context().get_context();
        Some(state.eval_abstract_location(parameter, &context.project.runtime_memory_image))
    }

    fn eval_at_node(&self, node: NodeIndex, expression: &Expression) -> Option<Data> {
        if let NodeValue::Value(state) = self.get_node_value(node)? {
            Some(state.eval(expression))
        } else {
            None
        }
    }
}
