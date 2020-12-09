use crate::abstract_domain::{
    AbstractDomain, AbstractIdentifier, BitvectorDomain, HasByteSize, MemRegion, RegisterDomain,
};
use crate::analysis::pointer_inference::Data;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::collections::HashMap;

use super::Taint;

/// The state object of the taint analysis representing all known tainted memory and register values.
#[derive(Serialize, Deserialize, Debug, Eq, Clone)]
pub struct State {
    /// The set of currently tainted registers.
    register_taint: HashMap<Variable, Taint>,
    /// The Taint contained in memory objects
    memory_taint: HashMap<AbstractIdentifier, MemRegion<Taint>>,
    /// The state of the pointer inference analysis.
    /// Used only for preventing unneccessary recomputation during handling of `Def`s in a basic block.
    /// It is set when handling `Def`s (except for the first `Def` in a block)
    /// provided that a corresponding pointer inference analysis state exists.
    /// Otherwise the field is ignored (including in the [merge](State::merge)-function) and usually set to `None`.
    #[serde(skip_serializing)]
    pointer_inference_state: Option<PointerInferenceState>,
}

impl PartialEq for State {
    /// Two states are equal if the same values are tainted in both states.
    ///
    /// The equality operator ignores the `pointer_inference_state` field,
    /// since it only denotes an intermediate value.
    fn eq(&self, other: &Self) -> bool {
        self.register_taint == other.register_taint && self.memory_taint == other.memory_taint
    }
}

impl AbstractDomain for State {
    /// Merge two states.
    /// Any value tainted in at least one input state is also tainted in the merged state.
    ///
    /// The used algorithm for merging the taints contained in memory regions is unsound
    /// when merging taints that intersect only partially.
    /// However, this should not have an effect in practice,
    /// since these values are usually unsound and unused by the program anyway.
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
                    // Unsound in theory for partially intersecting taints. Should not matter in practice.
                }
            } else {
                memory_taint.insert(tid.clone(), other_mem_region.clone());
            }
        }

        State {
            register_taint,
            memory_taint,
            pointer_inference_state: None, // At nodes this intermediate value can be safely forgotten.
        }
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a new state in which only the return values of the given extern symbol are tainted.
    pub fn new(
        taint_source: &ExternSymbol,
        stack_pointer_register: &Variable,
        pi_state: Option<&PointerInferenceState>,
    ) -> State {
        let mut state = State {
            register_taint: HashMap::new(),
            memory_taint: HashMap::new(),
            pointer_inference_state: None,
        };
        for return_arg in taint_source.return_values.iter() {
            match return_arg {
                Arg::Register(var) => {
                    state
                        .register_taint
                        .insert(var.clone(), Taint::Tainted(var.size));
                }
                Arg::Stack { offset, size } => {
                    if let Some(pi_state) = pi_state {
                        let address_exp = Expression::BinOp {
                            op: BinOpType::IntAdd,
                            lhs: Box::new(Expression::Var(stack_pointer_register.clone())),
                            rhs: Box::new(Expression::Const(
                                Bitvector::from_i64(*offset)
                                    .into_truncate(apint::BitWidth::from(
                                        stack_pointer_register.size,
                                    ))
                                    .unwrap(),
                            )),
                        };
                        if let Ok(address) = pi_state.eval(&address_exp) {
                            state.save_taint_to_memory(&address, Taint::Tainted(*size));
                        }
                    }
                }
            }
        }
        state
    }

    /// Evaluate whether the result of the given expression is tainted in the current state.
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

    /// Get the current pointer inference state if it is contained as an intermediate value in the state.
    pub fn get_pointer_inference_state(&self) -> Option<&PointerInferenceState> {
        self.pointer_inference_state.as_ref()
    }

    /// Set the current pointer inference state for `self`.
    pub fn set_pointer_inference_state(&mut self, pi_state: Option<PointerInferenceState>) {
        self.pointer_inference_state = pi_state;
    }

    /// Return whether the value at the given address (with the given size) is tainted.
    pub fn load_taint_from_memory(&self, address: &Data, size: ByteSize) -> Taint {
        let mut taint = Taint::Top(size);
        if let Data::Pointer(pointer) = address {
            for (mem_id, offset) in pointer.targets().iter() {
                if let (Some(mem_region), BitvectorDomain::Value(position)) =
                    (self.memory_taint.get(mem_id), offset)
                {
                    taint = taint.merge(&mem_region.get(position.clone(), size));
                }
            }
        }
        taint
    }

    /// Mark the value at the given address with the given taint.
    ///
    /// If the address may point to more than one object,
    /// we merge the taint object with the object at the targets,
    /// possibly tainting all possible targets.
    pub fn save_taint_to_memory(&mut self, address: &Data, taint: Taint) {
        if let Data::Pointer(pointer) = address {
            if pointer.targets().len() == 1 {
                for (mem_id, offset) in pointer.targets().iter() {
                    if let BitvectorDomain::Value(position) = offset {
                        if let Some(mem_region) = self.memory_taint.get_mut(mem_id) {
                            mem_region.add(taint, position.clone());
                        } else {
                            let mut mem_region = MemRegion::new(address.bytesize());
                            mem_region.add(taint, position.clone());
                            self.memory_taint.insert(mem_id.clone(), mem_region);
                        }
                    }
                }
            } else {
                for (mem_id, offset) in pointer.targets().iter() {
                    if let BitvectorDomain::Value(position) = offset {
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

    /// Return true if the memory object with the given ID contains a tainted value.
    pub fn check_mem_id_for_taint(&self, id: &AbstractIdentifier) -> bool {
        if let Some(mem_object) = self.memory_taint.get(&id) {
            for elem in mem_object.values() {
                if elem.is_tainted() {
                    return true;
                }
            }
        }
        false
    }

    /// If the given address points to the stack,
    /// return true if and only if the value at that stack position is tainted.
    /// If the given address points to a non-stack memory object,
    /// return true if the memory object contains any tainted value (at any position).
    pub fn check_if_address_points_to_taint(
        &self,
        address: Data,
        pi_state: &PointerInferenceState,
    ) -> bool {
        use crate::analysis::pointer_inference::object::ObjectType;
        if let Data::Pointer(pointer) = address {
            for (target, offset) in pointer.targets() {
                if let Ok(Some(ObjectType::Stack)) = pi_state.memory.get_object_type(target) {
                    // Only check if the value at the address is tainted
                    if let (Some(mem_object), BitvectorDomain::Value(target_offset)) =
                        (self.memory_taint.get(target), offset)
                    {
                        if let Some(taint) = mem_object.get_unsized(target_offset.clone()) {
                            if taint.is_tainted() {
                                return true;
                            }
                        }
                    }
                } else {
                    // Check whether the memory object contains any taint.
                    if self.check_mem_id_for_taint(target) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check whether a register in the given register list contains taint.
    /// Return `true` if taint was found and `false` if no taint was found.
    fn check_register_list_for_taint(
        &self,
        register_list: &[String],
        pi_state_option: Option<&PointerInferenceState>,
    ) -> bool {
        // Check whether a register contains taint
        for (register, taint) in &self.register_taint {
            if register_list
                .iter()
                .any(|reg_name| *reg_name == register.name)
                && !taint.is_top()
            {
                return true;
            }
        }
        // Check whether some memory object referenced by a register may contain taint
        if let Some(pi_state) = pi_state_option {
            for register_name in register_list {
                if let Some(register_value) = pi_state.get_register_by_name(register_name) {
                    if self.check_if_address_points_to_taint(register_value, pi_state) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check whether a generic function call may contain tainted values in its parameters.
    /// Since we don't know the actual calling convention of the call,
    /// we approximate the parameters with all parameter registers of the standard calling convention of the project.
    pub fn check_generic_function_params_for_taint(
        &self,
        project: &Project,
        pi_state_option: Option<&PointerInferenceState>,
    ) -> bool {
        if let Some(calling_conv) = project.get_standard_calling_convention() {
            self.check_register_list_for_taint(
                &calling_conv.parameter_register[..],
                pi_state_option,
            )
        } else {
            // No standard calling convention found. Assume everything may be parameters or referenced by parameters.
            !self.is_empty()
        }
    }

    /// Check whether the return registers may contain tainted values or point to objects containing tainted values.
    /// Since we don't know the actual return registers,
    /// we approximate them by all return registers of the standard calling convention of the project.
    pub fn check_return_values_for_taint(
        &self,
        project: &Project,
        pi_state_option: Option<&PointerInferenceState>,
    ) -> bool {
        if let Some(calling_conv) = project.get_standard_calling_convention() {
            self.check_register_list_for_taint(&calling_conv.return_register[..], pi_state_option)
        } else {
            // No standard calling convention found. Assume everything may be return values or referenced by return values.
            !self.is_empty()
        }
    }

    /// Remove the taint from all registers not contained in the callee-saved register list of the given calling convention.
    pub fn remove_non_callee_saved_taint(&mut self, calling_conv: &CallingConvention) {
        self.register_taint = self
            .register_taint
            .iter()
            .filter_map(|(register, taint)| {
                if calling_conv
                    .callee_saved_register
                    .iter()
                    .any(|callee_saved_reg| register.name == *callee_saved_reg)
                {
                    Some((register.clone(), *taint))
                } else {
                    None
                }
            })
            .collect();
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
        use std::iter::FromIterator;
        let register: Vec<(String, Value)> = self
            .register_taint
            .iter()
            .map(|(var, data)| (var.name.clone(), json!(format!("{}", data))))
            .collect();
        let mut memory = Vec::new();
        for (tid, mem_region) in self.memory_taint.iter() {
            let mut elements = Vec::new();
            for (offset, elem) in mem_region.iter() {
                elements.push((offset.to_string(), json!(elem.to_string())));
            }
            memory.push((format!("{}", tid), Value::Object(Map::from_iter(elements))));
        }
        let mut state_map = Vec::new();
        state_map.push((
            "register".to_string(),
            Value::Object(Map::from_iter(register)),
        ));
        state_map.push(("memory".to_string(), Value::Object(Map::from_iter(memory))));

        Value::Object(Map::from_iter(state_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abstract_domain::*;

    impl State {
        pub fn mock() -> State {
            State {
                register_taint: HashMap::new(),
                memory_taint: HashMap::new(),
                pointer_inference_state: None,
            }
        }

        pub fn mock_with_pi_state() -> (State, PointerInferenceState) {
            let arg1 = Arg::Register(register("RAX"));
            let arg2 = Arg::Stack {
                offset: 0,
                size: ByteSize::new(8),
            };
            let pi_state = PointerInferenceState::new(&register("RSP"), Tid::new("func"));
            let symbol = ExternSymbol {
                tid: Tid::new("extern_symbol".to_string()),
                addresses: vec![],
                name: "extern_symbol".into(),
                calling_convention: None,
                parameters: Vec::new(),
                return_values: vec![arg1, arg2],
                no_return: false,
            };
            let state = State::new(&symbol, &register("RSP"), Some(&pi_state));
            (state, pi_state)
        }
    }

    fn register(name: &str) -> Variable {
        Variable {
            name: name.into(),
            size: ByteSize::new(8),
            is_temp: false,
        }
    }

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(name.into(), ByteSize::new(8)),
        )
    }

    fn new_pointer_domain(location: &str, offset: i64) -> PointerDomain<BitvectorDomain> {
        let id = new_id(location);
        PointerDomain::new(id, bv(offset))
    }

    #[test]
    fn merge_state() {
        let taint = Taint::Tainted(ByteSize::new(8));
        let top = Taint::Top(ByteSize::new(8));

        let mut state = State::mock();
        state.set_register_taint(&register("RAX"), taint.clone());

        let mut other_state = State::mock();
        let address = Data::Pointer(new_pointer_domain("mem", 10));
        other_state.save_taint_to_memory(&address, taint);

        let merged_state = state.merge(&other_state);
        assert_eq!(
            merged_state.register_taint.get(&register("RAX")),
            Some(&taint)
        );
        assert_eq!(merged_state.register_taint.get(&register("RBX")), None);
        assert_eq!(
            merged_state.load_taint_from_memory(&address, ByteSize::new(8)),
            taint.clone()
        );
        let other_address = Data::Pointer(new_pointer_domain("mem", 18));
        assert_eq!(
            merged_state.load_taint_from_memory(&other_address, ByteSize::new(8)),
            top.clone()
        );
    }

    #[test]
    fn new_state() {
        let (state, pi_state) = State::mock_with_pi_state();
        let taint = Taint::Tainted(ByteSize::new(8));
        assert_eq!(state.register_taint.get(&register("RAX")), Some(&taint));
        assert_eq!(state.register_taint.get(&register("RSP")), None);
        let address = Expression::Var(register("RSP"));
        assert_eq!(
            state.load_taint_from_memory(&pi_state.eval(&address).unwrap(), ByteSize::new(8)),
            taint
        );
    }

    #[test]
    fn eval_expression() {
        let (state, _pi_state) = State::mock_with_pi_state();

        let expr = Expression::BinOp {
            lhs: Box::new(Expression::Var(register("RAX"))),
            op: BinOpType::IntAdd,
            rhs: Box::new(Expression::Var(register("RBX"))),
        };
        assert!(state.eval(&expr).is_tainted());

        let expr = Expression::UnOp {
            op: UnOpType::Int2Comp,
            arg: Box::new(Expression::Var(register("RSP"))),
        };
        assert!(state.eval(&expr).is_top());
    }
}
