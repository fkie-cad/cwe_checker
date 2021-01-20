#[cfg(test)]
use crate::{
    abstract_domain::{DataDomain, PointerDomain},
    intermediate_representation::CastOpType,
};

#[cfg(test)]
use super::*;

#[cfg(test)]
fn register(name: &str) -> Variable {
    Variable {
        name: name.into(),
        size: ByteSize::new(8),
        is_temp: false,
    }
}

#[cfg(test)]
fn extern_symbol(name: &str, return_args: Vec<Arg>) -> ExternSymbol {
    ExternSymbol {
        tid: Tid::new(name.to_string()),
        addresses: vec![],
        name: name.into(),
        calling_convention: None,
        parameters: Vec::new(),
        return_values: return_args,
        no_return: false,
    }
}

#[cfg(test)]
fn bin_op(op: BinOpType, lhs: Expression, rhs: Expression) -> Expression {
    Expression::BinOp {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

#[cfg(test)]
fn cast_op(op: CastOpType, arg: Expression) -> Expression {
    Expression::Cast {
        op,
        size: ByteSize::new(8),
        arg: Box::new(arg),
    }
}

#[cfg(test)]
fn variable_expr(name: &str) -> Expression {
    Expression::Var(register(name))
}

#[cfg(test)]
fn const_expr(value: Bitvector) -> Expression {
    Expression::Const(value)
}

#[cfg(test)]
fn subpiece_expr(low_byte: ByteSize, size: ByteSize, arg: Expression) -> Expression {
    Expression::Subpiece {
        low_byte,
        size,
        arg: Box::new(arg),
    }
}

#[cfg(test)]
fn int_add(name: &str, constant: Bitvector) -> Expression {
    bin_op(BinOpType::IntAdd, variable_expr(name), const_expr(constant))
}

#[cfg(test)]
fn bv(value: i64) -> BitvectorDomain {
    BitvectorDomain::Value(Bitvector::from_i64(value))
}

#[cfg(test)]
impl State {
    pub fn mock_with_pi_state() -> (State, PointerInferenceState) {
        let arg = Arg::Register(register("RAX"));
        let pi_state = PointerInferenceState::new(&register("RSP"), Tid::new("func"));
        let symbol = extern_symbol("system", vec![arg]);
        let mut state = State::new(&symbol, &register("RSP"), Some(&pi_state));
        state.pi_def_map = Some(HashMap::new());
        (state, pi_state)
    }

    pub fn set_pointer_inference_state_for_def(
        &mut self,
        pi_state: Option<PointerInferenceState>,
        def_tid: &Tid,
    ) {
        if let Some(pi_state) = pi_state {
            if let Some(pid_map) = self.pi_def_map.as_mut() {
                pid_map.insert(def_tid.clone(), pi_state);
            }
        }
    }

    pub fn set_pointer_inference_map(&mut self, pi_state_map: HashMap<Tid, PointerInferenceState>) {
        self.pi_def_map = Some(pi_state_map);
    }

    pub fn get_pointer_inference_state_at_def(
        &self,
        def_tid: &Tid,
    ) -> Option<&PointerInferenceState> {
        if let Some(pid_map) = self.pi_def_map.as_ref() {
            return pid_map.get(def_tid);
        }

        None
    }
}

#[cfg(test)]
struct Setup {
    state: State,
    pi_state: PointerInferenceState,
    rdi: Variable,
    rsi: Variable,
    rsp: Variable,
    constant: Bitvector,
    def_tid: Tid,
    stack_pointer: DataDomain<BitvectorDomain>,
    base_eight_offset: DataDomain<BitvectorDomain>,
    base_sixteen_offset: DataDomain<BitvectorDomain>,
}

#[cfg(test)]
impl Setup {
    fn new() -> Self {
        let (state, pi_state) = State::mock_with_pi_state();
        let stack_id = pi_state.stack_id.clone();
        Setup {
            state,
            pi_state,
            rdi: register("RDI"),
            rsi: register("RSI"),
            rsp: register("RSP"),
            constant: Bitvector::from_str_radix(16, "ffcc00").unwrap(),
            def_tid: Tid::new("def"),
            stack_pointer: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0))),
            base_eight_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-8))),
            base_sixteen_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16))),
        }
    }
}

#[test]
fn setting_expression_and_constants() {
    let mut setup = Setup::new();

    setup
        .pi_state
        .set_register(&setup.rdi, setup.base_eight_offset.clone());
    setup
        .state
        .set_pointer_inference_state_for_def(Some(setup.pi_state.clone()), &setup.def_tid);

    // Test Case 1: Constants
    let copy_const_expr = const_expr(setup.constant.clone());
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));

    setup.state.set_expression_taint_and_store_constants(
        &setup.def_tid,
        &setup.rdi,
        &copy_const_expr,
        &setup.rsp,
    );
    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(setup.state.string_constants.len(), 1);
    assert_eq!(
        *setup.state.string_constants.get(0).unwrap(),
        setup.constant
    );

    // Test Case 2: Variables
    let copy_var_expr = variable_expr("RSI");
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));

    setup.state.set_expression_taint_and_store_constants(
        &setup.def_tid,
        &setup.rdi,
        &copy_var_expr,
        &setup.rsp,
    );
    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(
        setup.state.get_register_taint(&setup.rsi),
        Some(&Taint::Tainted(setup.rsi.size))
    );

    // Test Case 2.5: Stack Pointer Assignment
    let stack_expression = variable_expr("RSP");
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));
    setup.state.set_expression_taint_and_store_constants(
        &setup.def_tid,
        &setup.rdi,
        &stack_expression,
        &setup.rsp,
    );
    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.stack_pointer, &setup.pi_state),
        true
    );

    // Test Case 3: Bin Ops
    let bin_op_expr = int_add("RBP", Bitvector::from_i8(-8));
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));

    setup.state.set_expression_taint_and_store_constants(
        &setup.def_tid,
        &setup.rdi,
        &bin_op_expr,
        &setup.rsp,
    );
    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        true
    );

    // Test Case 4: Any other Expression
    let cast_expr = cast_op(
        CastOpType::IntZExt,
        subpiece_expr(ByteSize::new(0), ByteSize::new(4), variable_expr("RDI")),
    );
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));
    setup.state.set_expression_taint_and_store_constants(
        &setup.def_tid,
        &setup.rdi,
        &cast_expr,
        &setup.rsp,
    );
    assert_eq!(
        setup.state.get_register_taint(&setup.rdi),
        Some(&Taint::Tainted(setup.rdi.size))
    );
}

#[test]
fn tainting_values_to_be_stored() {
    let mut setup = Setup::new();

    // Test Case: Memory target is tainted. --> Taint the input register
    setup
        .pi_state
        .set_register(&setup.rdi, setup.base_eight_offset.clone());
    setup
        .state
        .set_pointer_inference_state_for_def(Some(setup.pi_state.clone()), &setup.def_tid);
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .state
        .taint_value_to_be_stored(&setup.def_tid, &setup.rdi, &variable_expr("RSI"));
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
    assert_eq!(
        setup.state.get_register_taint(&setup.rsi),
        Some(&Taint::Tainted(setup.rsi.size))
    );

    // Test Case: Memory target is not tainted. --> Do nothing
    setup.state.register_taint.remove(&setup.rsi);
    setup
        .pi_state
        .set_register(&setup.rdi, setup.base_sixteen_offset.clone());
    setup
        .state
        .set_pointer_inference_state_for_def(Some(setup.pi_state.clone()), &setup.def_tid);
    setup
        .state
        .taint_value_to_be_stored(&setup.def_tid, &setup.rdi, &variable_expr("RSI"));
    assert_eq!(setup.state.get_register_taint(&setup.rsi), None);
}

#[test]
fn removing_memory_taint_at_target() {
    let mut setup = Setup::new();

    // Test Case: Memory was tainted and taint is removed
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset.clone(), &setup.pi_state),
        true
    );
    setup
        .state
        .remove_mem_taint_at_target(&setup.base_eight_offset);
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );

    // Test Case: Memory was not tainted and nothing happens
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_sixteen_offset.clone(), &setup.pi_state),
        false
    );
    setup
        .state
        .remove_mem_taint_at_target(&setup.base_sixteen_offset);
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state),
        false
    );
}

#[test]
fn saving_taint_to_memory() {
    let mut setup = Setup::new();

    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset.clone(), &setup.pi_state),
        false
    );
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset.clone(), &setup.pi_state),
        true
    );
}

#[test]
fn removing_non_parameter_taints_for_generic_function() {
    let mut setup = Setup::new();
    let mut mock_project = Project::mock_empty();
    mock_project
        .calling_conventions
        .push(CallingConvention::mock());

    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rdi.size));
    setup
        .state
        .set_register_taint(&setup.rsi, Taint::Tainted(setup.rsi.size));

    setup
        .state
        .remove_non_parameter_taints_for_generic_function(&mock_project);

    assert_eq!(
        setup.state.get_register_taint(&setup.rdi),
        Some(&Taint::Tainted(setup.rdi.size))
    );
    assert_eq!(setup.state.get_register_taint(&setup.rsi), None);
}

#[test]
fn removing_non_callee_saved_taint() {
    let mut setup = Setup::new();
    let cconv = CallingConvention::mock();
    let rbp_reg = register("RBP");
    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rsi.size));
    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));

    setup.state.remove_non_callee_saved_taint(&cconv);

    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(
        setup.state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
}

#[test]
fn removing_all_but_return() {
    let mut setup = Setup::new();
    let mut return_regs: HashSet<String> = HashSet::new();
    return_regs.insert("RAX".to_string());
    let rax_reg = register("RAX");

    setup
        .state
        .set_register_taint(&setup.rdi, Taint::Tainted(setup.rsi.size));
    setup
        .state
        .set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));

    setup
        .state
        .remove_all_except_return_register_taints(return_regs);

    assert_eq!(setup.state.get_register_taint(&setup.rdi), None);
    assert_eq!(
        setup.state.get_register_taint(&rax_reg),
        Some(&Taint::Tainted(rax_reg.size))
    );
}

#[test]
fn checking_if_address_points_to_taint() {
    let mut setup = Setup::new();
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        true
    );
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state),
        false
    );
}

#[test]
fn checking_return_registers_for_taint() {
    let mut setup = Setup::new();
    let rax_reg = register("RAX");
    let rdi_reg = register("RDI");

    // Test Case: Empty Taint
    assert_eq!(
        setup
            .state
            .check_return_registers_for_taint(vec!["RAX".to_string()]),
        false
    );

    // Test Case: No return register tainted
    setup
        .state
        .set_register_taint(&rdi_reg, Taint::Tainted(rdi_reg.size));
    assert_eq!(
        setup
            .state
            .check_return_registers_for_taint(vec!["RAX".to_string()]),
        false
    );

    // Test Case: Return register tainted
    setup
        .state
        .set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));
    assert_eq!(
        setup
            .state
            .check_return_registers_for_taint(vec!["RAX".to_string()]),
        true
    );
}
