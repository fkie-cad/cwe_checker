use std::collections::{HashMap, HashSet};

use crate::{
    abstract_domain::{
        AbstractDomain, AbstractIdentifier, DataDomain, IntervalDomain, MemRegion, SizedDomain,
        TryToBitvec,
    },
    analysis::pointer_inference::{Data, State as PointerInferenceState},
    checkers::cwe_476::Taint,
    intermediate_representation::{
        Arg, CallingConvention, Expression, ExternSymbol, Project, Sub, Variable,
    },
    prelude::*,
    utils::binary::RuntimeMemoryImage,
};

#[derive(Serialize, Deserialize, Debug, Eq, Clone)]
pub struct State {
    /// The set of currently tainted registers.
    register_taint: HashMap<Variable, Taint>,
    /// The Taint contained in memory objects
    memory_taint: HashMap<AbstractIdentifier, MemRegion<Taint>>,
    /// The set of addresses in the binary where string constants reside
    string_constants: HashSet<String>,
    /// A map from Def Tids to their corresponding pointer inference state.
    /// The pointer inference states are calculated in a forward manner
    /// from the BlkStart node when entering a BlkEnd node through a jump.
    #[serde(skip_serializing)]
    pi_def_map: Option<HashMap<Tid, PointerInferenceState>>,
    /// Holds the currently analyzed subroutine term
    current_sub: Option<Term<Sub>>,
}

impl PartialEq for State {
    /// Two states are equal if the same values are tainted in both states.
    ///
    /// The equality operator ignores the `pi_def_map` field,
    /// since it only denotes an intermediate value.
    fn eq(&self, other: &Self) -> bool {
        self.register_taint == other.register_taint
            && self.memory_taint == other.memory_taint
            && self.string_constants == other.string_constants
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

        let constants = self.string_constants.clone();
        constants.union(&other.string_constants);

        State {
            register_taint,
            memory_taint,
            string_constants: constants,
            pi_def_map: None, // At nodes this intermediate value can be safely forgotten.
            current_sub: self.current_sub.clone(),
        }
    }

    /// The state has no explicit Top element.
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a new state in which only the parameter values of the given extern symbol are tainted.
    pub fn new(
        taint_source: &ExternSymbol,
        stack_pointer_register: &Variable,
        pi_state: Option<&PointerInferenceState>,
        current_sub: &Term<Sub>,
    ) -> State {
        let mut state = State {
            register_taint: HashMap::new(),
            memory_taint: HashMap::new(),
            string_constants: HashSet::new(),
            pi_def_map: None,
            current_sub: Some(current_sub.clone()),
        };
        for parameter in taint_source.parameters.iter() {
            match parameter {
                Arg::Register { var, .. } => {
                    state
                        .register_taint
                        .insert(var.clone(), Taint::Tainted(var.size));
                }
                Arg::Stack { offset, size, .. } => {
                    if let Some(pi_state) = pi_state {
                        let address_exp =
                            Expression::Var(stack_pointer_register.clone()).plus_const(*offset);
                        let address = pi_state.eval(&address_exp);
                        state.save_taint_to_memory(&address, Taint::Tainted(*size));
                    }
                }
            }
        }
        state
    }

    /// Mark the value at the given address with the given taint.
    ///
    /// If the address points to more than one object,
    /// we merge the taint object with the object at the targets,
    /// possibly tainting all possible targets.
    pub fn save_taint_to_memory(&mut self, address: &Data, taint: Taint) {
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

    /// Returns the sub of the currently analysed nodes.
    pub fn get_current_sub(&self) -> &Option<Term<Sub>> {
        &self.current_sub
    }

    /// Set the current sub to locate the analysis.
    pub fn set_current_sub(&mut self, current_sub: &Term<Sub>) {
        self.current_sub = Some(current_sub.clone());
    }

    /// Sets the pointer inference to definition map for the current state.
    pub fn set_pi_def_map(&mut self, pi_def_map: Option<HashMap<Tid, PointerInferenceState>>) {
        self.pi_def_map = pi_def_map;
    }

    /// Gets the taint state of a register if there is one.
    pub fn get_register_taint(&self, var: &Variable) -> Option<&Taint> {
        self.register_taint.get(var)
    }

    /// Returns an iterator over currently tainted registers.
    pub fn get_register_taints(&self) -> std::collections::hash_map::Iter<Variable, Taint> {
        self.register_taint.iter()
    }

    /// Remove all memory taints
    pub fn remove_all_memory_taints(&mut self) {
        self.memory_taint = HashMap::new();
    }

    /// Remove all register taints
    pub fn remove_all_register_taints(&mut self) {
        self.register_taint = HashMap::new();
    }

    /// Gets the callee saved taints from the register taints.
    pub fn get_callee_saved_register_taints(
        &self,
        calling_conv: &CallingConvention,
    ) -> HashMap<Variable, Taint> {
        self.register_taint
            .clone()
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
            .collect()
    }

    /// Gets the string constant saved at the given address and saves it to the string constants field.
    pub fn evaluate_constant(
        &mut self,
        runtime_memory_image: &RuntimeMemoryImage,
        constant: Bitvector,
    ) {
        if runtime_memory_image.is_global_memory_address(&constant) {
            match runtime_memory_image.read_string_until_null_terminator(&constant) {
                Ok(format_string) => {
                    self.string_constants.insert(format_string.to_string());
                }
                // TODO: Change to log
                Err(e) => panic!("{}", e),
            }
        }
    }

    /// Taints input registers and evaluates constant memory addresses for simple assignments
    /// and taints memory if a pointer is overwritten.
    /// The taint on the result register is removed.
    pub fn set_expression_taint_and_store_constants(
        &mut self,
        def_tid: &Tid,
        result: &Variable,
        expression: &Expression,
        stack_pointer_register: &Variable,
        runtime_memory_image: &RuntimeMemoryImage,
    ) {
        self.remove_register_taint(result);
        match expression {
            Expression::Const(constant) => {
                self.evaluate_constant(runtime_memory_image, constant.clone())
            }
            Expression::Var(var) => self.taint_variable_input(var, stack_pointer_register, def_tid),
            Expression::BinOp { .. } => {
                if let Some(pid_map) = self.pi_def_map.as_ref() {
                    if let Some(pi_state) = pid_map.get(def_tid) {
                        let address = pi_state.get_register(result);
                        self.save_taint_to_memory(&address, Taint::Tainted(result.size));
                    }
                }
            }
            Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => self.taint_def_input_register(
                arg,
                stack_pointer_register,
                def_tid,
                runtime_memory_image,
            ),
            _ => (),
        }
    }

    /// Taints the input register of a store instruction and removes the memory taint at the target address.
    pub fn taint_value_to_be_stored(
        &mut self,
        def_tid: &Tid,
        target: &Expression,
        value: &Expression,
        stack_pointer_register: &Variable,
        runtime_memory_image: &RuntimeMemoryImage,
    ) {
        if let Some(pid_map) = self.pi_def_map.as_ref() {
            if let Some(pi_state) = pid_map.get(def_tid) {
                let address = pi_state.eval(target);
                if self.address_points_to_taint(address.clone(), pi_state) {
                    self.taint_def_input_register(
                        value,
                        stack_pointer_register,
                        def_tid,
                        runtime_memory_image,
                    );
                    self.remove_mem_taint_at_target(&address);
                }
            }
        }
    }

    /// Taints all input register of an expression.
    pub fn taint_def_input_register(
        &mut self,
        expr: &Expression,
        stack_pointer_register: &Variable,
        def_tid: &Tid,
        runtime_memory_image: &RuntimeMemoryImage,
    ) {
        match expr {
            Expression::Const(constant) => {
                self.evaluate_constant(runtime_memory_image, constant.clone())
            }
            Expression::Var(var) => self.taint_variable_input(var, stack_pointer_register, def_tid),
            Expression::BinOp { lhs, rhs, .. } => {
                self.taint_def_input_register(
                    lhs,
                    stack_pointer_register,
                    def_tid,
                    runtime_memory_image,
                );
                self.taint_def_input_register(
                    rhs,
                    stack_pointer_register,
                    def_tid,
                    runtime_memory_image,
                );
            }
            Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => self.taint_def_input_register(
                arg,
                stack_pointer_register,
                def_tid,
                runtime_memory_image,
            ),
            _ => (),
        }
    }

    /// Either taints the input register or a memory position if it is the stack pointer register.
    pub fn taint_variable_input(
        &mut self,
        var: &Variable,
        stack_pointer_register: &Variable,
        def_tid: &Tid,
    ) {
        if var.name == stack_pointer_register.name {
            if let Some(pid_map) = self.pi_def_map.as_ref() {
                if let Some(pi_state) = pid_map.get(def_tid) {
                    let address = pi_state.get_register(stack_pointer_register);
                    self.save_taint_to_memory(
                        &address,
                        Taint::Tainted(stack_pointer_register.size),
                    );
                }
            }
        } else {
            self.set_register_taint(var, Taint::Tainted(var.size));
        }
    }

    /// Remove the taint in the specified memory regions at the specified offsets.
    pub fn remove_mem_taint_at_target(&mut self, address: &Data) {
        for (mem_id, offset) in address.get_relative_values() {
            if let (Some(mem_region), Ok(position)) =
                (self.memory_taint.get_mut(mem_id), offset.try_to_bitvec())
            {
                if let Some(taint) = mem_region.get_unsized(position.clone()) {
                    mem_region.remove(position, Bitvector::from_u64(u64::from(taint.bytesize())));
                }
            }
        }
    }

    /// Set the taint of a register.
    pub fn set_register_taint(&mut self, register: &Variable, taint: Taint) {
        if taint.is_top() {
            self.register_taint.remove(register);
        } else {
            self.register_taint.insert(register.clone(), taint);
        }
    }

    /// Removes a specified register taint
    pub fn remove_register_taint(&mut self, register: &Variable) {
        self.register_taint.remove(register);
    }

    /// Return true if the memory object with the given ID contains a tainted value.
    pub fn check_mem_id_for_taint(&self, id: &AbstractIdentifier) -> bool {
        if let Some(mem_object) = self.memory_taint.get(id) {
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
    pub fn address_points_to_taint(&self, address: Data, pi_state: &PointerInferenceState) -> bool {
        use crate::analysis::pointer_inference::object::ObjectType;
        for (target, offset) in address.get_relative_values() {
            if let Ok(Some(ObjectType::Stack)) = pi_state.memory.get_object_type(target) {
                // Only check if the value at the address is tainted
                if let (Some(mem_object), Ok(target_offset)) =
                    (self.memory_taint.get(target), offset.try_to_bitvec())
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
        false
    }

    /// Removes all taints of registers that are not generic function parameters.
    /// Since we don't know the actual calling convention of the call,
    /// we approximate the parameters with all parameter registers of the standard calling convention of the project.
    pub fn remove_non_parameter_taints_for_generic_function(&mut self, project: &Project) {
        if let Some(calling_conv) = project.get_standard_calling_convention() {
            let register_names: HashSet<String> = calling_conv
                .integer_parameter_register
                .iter()
                .chain(calling_conv.float_parameter_register.iter())
                .cloned()
                .collect();
            let taints = self.register_taint.clone();
            for (register, _) in taints.iter() {
                if register_names.get(&register.name).is_none() {
                    self.register_taint.remove(register);
                }
            }
        }
    }

    /// Removes the taint of a callee saved register if it was identified as the return target of
    /// a string symbol.
    pub fn remove_callee_saved_taint_if_destination_parameter(
        &mut self,
        destination_address: &DataDomain<IntervalDomain>,
        pi_state: &PointerInferenceState,
        standard_cconv: &CallingConvention,
    ) {
        for (var, _) in self.get_callee_saved_register_taints(standard_cconv).iter() {
            let callee_saved_address = pi_state.eval(&Expression::Var(var.clone()));
            if callee_saved_address == *destination_address {
                self.remove_register_taint(var);
            }
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

    /// Remove all register taints except for the return register taints if available
    /// This clears the state on the return stub edge
    pub fn remove_all_except_return_register_taints(&mut self, return_registers: HashSet<String>) {
        let tainted = self.register_taint.clone();
        for (register, _taint) in tainted {
            if return_registers.get(&register.name).is_none() {
                self.register_taint.remove(&register);
            }
        }
    }

    /// Check whether `self` contains any taint at all.
    pub fn is_empty(&self) -> bool {
        self.memory_taint.is_empty() && self.register_taint.is_empty()
    }

    /// Checks whether the return registers are contained in the current tainted registers
    pub fn check_return_registers_for_taint(&self, register_list: Vec<String>) -> bool {
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

        false
    }

    /// Merges callee saved register taints into the current state
    pub fn merge_callee_saved_taints_from_return_state(
        &mut self,
        return_state: &State,
        calling_convention: Option<&CallingConvention>,
    ) {
        if let Some(calling_conv) = calling_convention {
            let callee_saved_registers: HashSet<String> =
                calling_conv.callee_saved_register.iter().cloned().collect();
            for (variable, taint) in return_state.get_register_taints() {
                if callee_saved_registers.get(&variable.name).is_some() {
                    self.set_register_taint(variable, *taint);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
