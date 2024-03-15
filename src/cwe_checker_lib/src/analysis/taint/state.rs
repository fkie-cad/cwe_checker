//! Property space of a taint analysis.
//!
//! Instances of the [`State`] type represent the taint state of memory and
//! registers at a certain location in the program.

use crate::abstract_domain::AbstractLocation;
use crate::abstract_domain::{
    AbstractDomain, AbstractIdentifier, MemRegion, RegisterDomain, SizedDomain, TryToBitvec,
};
use crate::analysis::graph::NodeIndex;
use crate::analysis::pointer_inference::Data as PiData;
use crate::analysis::vsa_results::VsaResult;
use crate::intermediate_representation::*;
use crate::prelude::*;

use std::collections::HashMap;

use super::Taint;

/// The state object of the taint analysis representing all known tainted memory
/// and register values at a certain location within the program.
///
/// The `POINTER_TAINT` const generic can be used to select if the state should
/// treat pointers to tainted memory as tainted when analyzing function calls
/// and returns.
#[derive(Serialize, Deserialize, Debug, Eq, Clone, Default)]
pub struct State<const POINTER_TAINT: bool = true> {
    /// The set of currently tainted registers.
    register_taint: HashMap<Variable, Taint>,
    /// The Taint contained in memory objects
    memory_taint: HashMap<AbstractIdentifier, MemRegion<Taint>>,
}

impl<const POINTER_TAINT: bool> PartialEq for State<POINTER_TAINT> {
    /// Two states are equal if the same values are tainted in both states.
    fn eq(&self, other: &Self) -> bool {
        self.register_taint == other.register_taint && self.memory_taint == other.memory_taint
    }
}

impl<const POINTER_TAINT: bool> AbstractDomain for State<POINTER_TAINT> {
    /// Merge two states.
    ///
    /// Any value tainted in at least one input state is also tainted in the
    /// merged state.
    ///
    /// The used algorithm for merging the taints contained in memory regions is
    /// unsound when merging taints that intersect only partially. However, this
    /// should not have an effect in practice, since these values are usually
    /// unsound and unused by the program anyway.
    fn merge(&self, other: &Self) -> Self {
        let mut register_taint = self.register_taint.clone();
        for (var, other_taint) in other.register_taint.iter() {
            if let Some(taint) = self.register_taint.get(var) {
                register_taint.insert(var.clone(), taint.merge(other_taint));
            } else {
                register_taint.insert(var.clone(), *other_taint);
            }
        }

        let mut memory_taint = self.memory_taint.clone();
        for (tid, other_mem_region) in other.memory_taint.iter() {
            if let Some(mem_region) = memory_taint.get_mut(tid) {
                for (index, taint) in other_mem_region.iter() {
                    mem_region.insert_at_byte_index(*taint, *index);
                    // Unsound in theory for partially intersecting taints.
                    // Should not matter in practice.
                }
            } else {
                memory_taint.insert(tid.clone(), other_mem_region.clone());
            }
        }

        State {
            register_taint,
            memory_taint,
        }
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl<const POINTER_TAINT: bool> State<POINTER_TAINT> {
    /// Returns an empty state.
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Returns a state where only return values of the extern call are tainted.
    ///
    /// Get a new state in which only the return values of the given call to an
    /// extern symbol are tainted.
    pub fn new_return(
        taint_source: &ExternSymbol,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        return_node: NodeIndex,
    ) -> Self {
        let mut state = Self {
            register_taint: HashMap::new(),
            memory_taint: HashMap::new(),
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
    /// object with the object at the targets, possibly tainting all possible
    /// targets.
    pub fn save_taint_to_memory(&mut self, address: &PiData, taint: Taint) {
        if let Some((mem_id, offset)) = address.get_if_unique_target() {
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
        self.memory_taint = HashMap::new();
    }

    /// Set the taint of a register.
    pub fn set_register_taint(&mut self, register: &Variable, taint: Taint) {
        if taint.is_top() {
            self.register_taint.remove(register);
        } else {
            self.register_taint.insert(register.clone(), taint);
        }
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
    // FIXME: The original implementation in CWE476 distinguished between stack
    // memory and all other memory objects. If the given address points to a
    // non-stack memory object, it returns true if the memory object contains
    // any tainted value (at any position).
    pub fn check_if_address_points_to_taint(&self, address: PiData) -> bool {
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

    /// Check if any register in the given register list contains taint (or, if
    /// `POINTER_TAINT` is selected, points to tainted memory).
    ///
    /// Returns `true` if taint was found and `false` if no taint was found.
    fn check_register_list_for_taint(
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
                .is_some_and(|register_value| self.check_if_address_points_to_taint(register_value))
            )
        })
    }

    /// Check if a generic function call may contain tainted values in its
    /// parameters (or, if `POINTER_TAINT` is selected, receives pointers to
    /// tainted memory).
    ///
    /// Since we don't know the actual parameters of the call, we approximate
    /// the parameters with all parameter registers of the calling convention of
    /// the function or of the standard calling convention of the project.
    ///
    /// In case no standard calling convention is found. We assume everything
    /// may be parameters or referenced by parameters, i.e., we assume the
    /// parameters of the call are tainted iff there is taint in the state.
    pub fn check_generic_function_params_for_taint(
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
            self.check_register_list_for_taint(vsa_result, call_tid, &all_parameters)
        } else {
            !self.is_empty()
        }
    }

    /// Check if the return registers may contain tainted values (or, if
    /// `POINTER_TAINT` is selected, point to tainted memory).
    ///
    /// Since we don't know the actual return registers, we approximate them by
    /// all return registers of the calling convention of the function or of the
    /// standard calling convention of the project.
    ///
    /// If no standard calling convention is found, we assume that everything
    /// may be a return value or referenced by return values.
    pub fn check_return_values_for_taint(
        &self,
        vsa_result: &impl VsaResult<ValueDomain = PiData>,
        return_tid: &Tid,
        project: &Project,
        calling_convention_hint: &Option<String>,
    ) -> bool {
        if let Some(calling_conv) = project.get_specific_calling_convention(calling_convention_hint)
        {
            self.check_register_list_for_taint(
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
    pub fn check_extern_parameters_for_taint(
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
                        self.check_if_address_points_to_taint(register_value)
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
                        self.check_if_address_points_to_taint(stack_value)
                    }))
                },
            }
        })
    }

    /// Check whether `self` contains any taint at all.
    pub fn is_empty(&self) -> bool {
        self.memory_taint.is_empty() && self.register_taint.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::graph::NodeIndex;
    use crate::analysis::pointer_inference::{tests::MockVsaResult, State as PiState, ValueDomain};
    use crate::{abstract_domain::*, expr, variable};
    use std::collections::BTreeSet;

    impl State {
        pub fn mock() -> State {
            State {
                register_taint: HashMap::new(),
                memory_taint: HashMap::new(),
            }
        }

        pub fn mock_with_pi_state() -> (State, PiState) {
            let ret1 = Arg::Register {
                expr: expr!("RAX:8"),
                data_type: None,
            };
            let ret2 = Arg::Stack {
                address: expr!("RSP:8"),
                size: ByteSize::new(8),
                data_type: None,
            };
            let symbol = ExternSymbol {
                tid: Tid::new("extern_symbol".to_string()),
                addresses: vec![],
                name: "extern_symbol".into(),
                calling_convention: None,
                parameters: Vec::new(),
                return_values: vec![ret1, ret2],
                no_return: false,
                has_var_args: false,
            };

            let pi_state = PiState::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new());
            let vsa_result = MockVsaResult::new(pi_state.clone(), None, None, None);

            let state = State::new_return(&symbol, &vsa_result, NodeIndex::new(42));

            (state, pi_state)
        }
    }

    fn bv(value: i64) -> ValueDomain {
        ValueDomain::from(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(variable!(format!("{}:8", name))),
        )
    }

    fn new_pointer(location: &str, offset: i64) -> DataDomain<ValueDomain> {
        let id = new_id(location);
        DataDomain::from_target(id, bv(offset))
    }

    #[test]
    fn merge_state() {
        let taint = Taint::Tainted(ByteSize::new(8));
        let top = Taint::Top(ByteSize::new(8));

        let mut state = State::mock();
        state.set_register_taint(&variable!("RAX:8"), taint.clone());

        let mut other_state = State::mock();
        let address = new_pointer("mem", 10);
        other_state.save_taint_to_memory(&address, taint);

        let merged_state = state.merge(&other_state);
        assert_eq!(
            merged_state.register_taint.get(&variable!("RAX:8")),
            Some(&taint)
        );
        assert_eq!(merged_state.register_taint.get(&variable!("RBX:8")), None);
        assert_eq!(
            merged_state.load_taint_from_memory(&address, ByteSize::new(8)),
            taint.clone()
        );
        let other_address = new_pointer("mem", 18);
        assert_eq!(
            merged_state.load_taint_from_memory(&other_address, ByteSize::new(8)),
            top.clone()
        );
    }

    #[test]
    fn new_state() {
        let (state, pi_state) = State::mock_with_pi_state();
        let taint = Taint::Tainted(ByteSize::new(8));

        assert_eq!(state.register_taint.get(&variable!("RAX:8")), Some(&taint));
        assert_eq!(state.register_taint.get(&variable!("RSP:8")), None);
        let address = Expression::Var(variable!("RSP:8"));
        assert_eq!(
            state.load_taint_from_memory(&pi_state.eval(&address), ByteSize::new(8)),
            taint
        );
    }

    #[test]
    fn eval_expression() {
        let (state, _pi_state) = State::mock_with_pi_state();

        let expr = expr!("RAX:8 + RBX:8");
        assert!(state.eval(&expr).is_tainted());

        let expr = Expression::UnOp {
            op: UnOpType::Int2Comp,
            arg: Box::new(Expression::Var(variable!("RSP:8"))),
        };
        assert!(state.eval(&expr).is_top());
    }

    #[test]
    fn check_extern_parameter_for_taint() {
        let (mut state, pi_state) = State::mock_with_pi_state();
        let vsa_results = MockVsaResult::new(pi_state, None, None, None);

        assert_eq!(
            state.check_extern_parameters_for_taint(
                &vsa_results,
                &ExternSymbol::mock_x64("mock_symbol"),
                &Tid::new("call".to_string()),
            ),
            false
        );

        state.set_register_taint(&variable!("RDI:8"), Taint::Tainted(ByteSize::new(8)));
        assert_eq!(
            state.check_extern_parameters_for_taint(
                &vsa_results,
                &ExternSymbol::mock_x64("mock_symbol"),
                &Tid::new("call".to_string()),
            ),
            true
        );
    }
}
