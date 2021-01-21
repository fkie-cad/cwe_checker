use super::*;

use crate::analysis::backward_interprocedural_fixpoint::Context as BackwardContext;
use crate::{
    abstract_domain::{BitvectorDomain, DataDomain, HasByteSize, PointerDomain},
    analysis::pointer_inference::{Data, State as PointerInferenceState},
    bil::Bitvector,
    intermediate_representation::Variable,
};

#[cfg(test)]
fn mock_block(tid: &str) -> Term<Blk> {
    Term {
        tid: Tid::new(tid),
        term: Blk {
            defs: Vec::new(),
            jmps: Vec::new(),
        },
    }
}

#[cfg(test)]
fn mock_assign(tid: &str, var_name: &str, expr: Expression) -> Term<Def> {
    Term {
        tid: Tid::new(tid),
        term: Def::Assign {
            var: register(var_name),
            value: expr,
        },
    }
}

#[cfg(test)]
fn mock_load(tid: &str, var_name: &str, expr: Expression) -> Term<Def> {
    Term {
        tid: Tid::new(tid),
        term: Def::Load {
            var: register(var_name),
            address: expr,
        },
    }
}

#[cfg(test)]
fn mock_store(tid: &str, target: Expression, source: Expression) -> Term<Def> {
    Term {
        tid: Tid::new(tid),
        term: Def::Store {
            address: target,
            value: source,
        },
    }
}

#[cfg(test)]
fn mock_jump(tid: &str, target_tid: &str, return_tid: &str) -> Term<Jmp> {
    Term {
        tid: Tid::new(tid),
        term: Jmp::Call {
            target: Tid::new(target_tid),
            return_: Some(Tid::new(return_tid)),
        },
    }
}

#[cfg(test)]
fn register(name: &str) -> Variable {
    Variable {
        name: name.into(),
        size: ByteSize::new(8),
        is_temp: false,
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
fn bin_op(op: BinOpType, lhs: Expression, rhs: Expression) -> Expression {
    Expression::BinOp {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
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
impl ExternSymbol {
    fn mock_string() -> Self {
        ExternSymbol {
            tid: Tid::new("sprintf"),
            addresses: vec!["UNKNOWN".to_string()],
            name: "sprintf".to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI"), Arg::mock_register("RSI")],
            return_values: vec![Arg::mock_register("RAX")],
            no_return: false,
        }
    }
}

#[cfg(test)]
struct Setup {
    project: Project,
    state: State,
    pi_state: PointerInferenceState,
    string_sym: ExternSymbol,
    taint_source: Term<Jmp>,
    base_eight_offset: DataDomain<BitvectorDomain>,
    base_sixteen_offset: DataDomain<BitvectorDomain>,
}

#[cfg(test)]
impl Setup {
    fn new() -> Self {
        let (state, pi_state) = State::mock_with_pi_state();
        let stack_id = pi_state.stack_id.clone();
        let taint_source = Term {
            tid: Tid::new("taint_source"),
            term: Jmp::Call {
                target: Tid::new("system"),
                return_: None,
            },
        };
        let mut project = Project::mock_empty();
        let mut sub = Sub::mock("func");
        let mut block1 = mock_block("block1");
        let block2 = mock_block("block2");
        let def1 = mock_assign("def1", "RBP", variable_expr("RSP"));
        let def2 = mock_assign("def2", "RDI", int_add("RBP", Bitvector::from_i64(-8)));
        let jump = mock_jump("call_string", "sprintf", "block2");
        block1.term.defs.push(def1);
        block1.term.defs.push(def2);
        block1.term.jmps.push(jump.clone());
        sub.term.blocks.push(block1);
        sub.term.blocks.push(block2);
        project
            .program
            .term
            .extern_symbols
            .push(ExternSymbol::mock_string());
        project
            .program
            .term
            .extern_symbols
            .push(ExternSymbol::mock());
        project.program.term.subs.push(sub);
        project.program.term.entry_points.push(Tid::new("func"));
        project.calling_conventions.push(CallingConvention::mock());

        Setup {
            project,
            state,
            pi_state,
            string_sym: ExternSymbol::mock_string(),
            taint_source,
            base_eight_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-8))),
            base_sixteen_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16))),
        }
    }
}

#[cfg(test)]
impl<'a> Context<'a> {
    fn mock(
        project: &'a Project,
        string_symbols: HashMap<Tid, &'a ExternSymbol>,
        pi_results: &'a PointerInferenceComputation<'a>,
    ) -> Self {
        let (cwe_sender, _) = crossbeam_channel::unbounded();
        Context::new(project, pi_results, string_symbols, cwe_sender)
    }
}

#[test]
fn setting_taint_source() {
    let setup = Setup::new();
    let current_sub = Sub::mock("func");

    let pi_results = PointerInferenceComputation::mock(&setup.project);
    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    context.set_taint_source(&setup.taint_source, &current_sub);
    assert_eq!(context.taint_source, Some(&setup.taint_source));
}

#[test]
fn tainting_string_function_parameters() {
    let mut setup = Setup::new();
    let rbp_reg = register("RBP"); // callee saved -> will point to RSP
    let rdi_reg = register("RDI"); // parameter 1 -> will point to RBP - 8
    let rsi_reg = register("RSI"); // parameter 2

    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .state
        .save_taint_to_memory(&setup.base_sixteen_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    let node_id = context
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    let new_state =
        context.taint_string_function_parameters(&setup.state, &setup.string_sym, *node_id);

    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state),
        true
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rsi_reg),
        Some(&Taint::Tainted(rsi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
}

#[test]
fn tainting_generic_function_parameters_and_removing_non_callee_saved() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");
    let rbp_reg = register("RBP");
    let rdi_reg = register("RDI");
    let rsi_reg = register("RSI");
    let rax_reg = register("RAX");

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));
    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    let mut string_syms: HashMap<Tid, &ExternSymbol> = HashMap::new();
    string_syms.insert(Tid::new("sprintf"), &setup.string_sym);
    let context = Context::mock(&setup.project, string_syms, &pi_results);
    let node_id = context
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    // Test Case 1: String Symbol
    let mut new_state = context.taint_generic_function_parameters_and_remove_non_callee_saved(
        &setup.state,
        &ExternSymbol::mock_string(),
        node_id.clone(),
    );

    // Parameter
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rsi_reg),
        Some(&Taint::Tainted(rsi_reg.size))
    );
    // Callee Saved
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
    // Non Callee Saved
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(new_state.get_register_taint(&rax_reg), None);

    new_state.remove_all_register_taints();
    new_state.set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));
    new_state.set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    new_state.set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));

    // Test Case 2: Other Extern Symbol
    new_state = context.taint_generic_function_parameters_and_remove_non_callee_saved(
        &new_state,
        &ExternSymbol::mock(),
        node_id.clone(),
    );

    // Parameter
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    // Callee Saved
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
    // Non Callee Saved
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(new_state.get_register_taint(&rax_reg), None);
    assert_eq!(new_state.get_register_taint(&rsi_reg), None);
}

#[test]
fn tainting_stack_parameters() {
    let setup = Setup::new();
    let offset = 4 as i64;
    let size = ByteSize::new(8);

    let stack_id = setup.pi_state.stack_id.clone();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    let call_source_node = context
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    let new_state =
        context.taint_stack_parameters(setup.state, call_source_node.clone(), offset, size);

    assert_eq!(
        new_state.check_if_address_points_to_taint(
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(4))),
            &setup.pi_state
        ),
        true
    );
}

#[test]
fn tainting_parameters() {
    let setup = Setup::new();
    let rdi_reg = register("RDI");
    let rsi_reg = register("RSI");
    let params = vec![
        Arg::Register(rdi_reg.clone()),
        Arg::Register(rsi_reg.clone()),
        Arg::Stack {
            offset: 4,
            size: ByteSize::new(8),
        },
    ];

    let stack_id = setup.pi_state.stack_id.clone();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    let call_source_node = context
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    let new_state = context.taint_parameters(&setup.state, params, call_source_node.clone());

    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rsi_reg),
        Some(&Taint::Tainted(rsi_reg.size))
    );

    assert_eq!(
        new_state.check_if_address_points_to_taint(
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(4))),
            &setup.pi_state
        ),
        true
    );
}

#[test]
fn creating_pi_def_map() {
    let setup = Setup::new();
    let rdi_reg = register("RDI");
    let def1 = Tid::new("def1");
    let def2 = Tid::new("def2");

    let stack_id = setup.pi_state.stack_id.clone();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();
    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);
    let start_node = context
        .block_start_node_map
        .get(&(def2.clone(), context.current_sub.unwrap().tid.clone()))
        .unwrap();

    let pi_def_map = context.create_pi_def_map(start_node.clone()).unwrap();

    for (def_tid, pi_state) in pi_def_map.iter() {
        if *def_tid == def1 {
            assert_eq!(
                pi_state.get_register(&rdi_reg).unwrap(),
                Data::new_top(rdi_reg.size)
            );
        } else if *def_tid == def2 {
            assert_eq!(
                pi_state.get_register(&rdi_reg).unwrap(),
                Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-8)))
            );
        }
    }
}

#[test]
fn getting_blk_start_node_if_last_def() {
    let setup = Setup::new();
    let def1 = mock_assign("def1", "RBP", variable_expr("RSP"));
    let def2 = mock_assign("def2", "RDI", int_add("RBP", Bitvector::from_i64(-8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();
    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);

    let start_node = context
        .block_start_node_map
        .get(&(def2.tid.clone(), context.current_sub.unwrap().tid.clone()))
        .unwrap();

    assert_eq!(context.get_blk_start_node_if_last_def(&def1), None);
    assert_eq!(
        context.get_blk_start_node_if_last_def(&def2),
        Some(start_node.clone())
    );
}

#[test]
fn getting_source_node() {
    let setup = Setup::new();
    let call_tid = Tid::new("call_string");

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();
    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);

    let blk_end_node_id = context
        .jmp_to_blk_end_node_map
        .get(&(call_tid.clone(), context.current_sub.unwrap().tid.clone()))
        .unwrap();

    assert_eq!(context.get_source_node(&call_tid), *blk_end_node_id);
}

#[test]
fn handling_assign_and_load() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");
    let rdi_reg = register("RDI");
    let mock_assign_register = mock_assign("assign", "R9", variable_expr("RDI"));
    let mock_assign_stack = mock_assign("stack_assign", "R9", variable_expr("RSP"));
    let mock_load = mock_load("load", "R9", variable_expr("RDI"));
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    let mut new_state = context
        .update_def(&setup.state, &mock_assign_register)
        .unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );

    // Test Case: None State
    new_state.remove_all_register_taints();
    assert_eq!(context.update_def(&new_state, &mock_assign_register), None);

    // Test Case: Assign RSP Register
    pi_map.insert(Tid::new("stack_assign"), setup.pi_state.clone());
    new_state.set_pointer_inference_map(pi_map.clone());

    new_state.set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    new_state = context.update_def(&new_state, &mock_assign_stack).unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0))),
            &setup.pi_state
        ),
        true
    );

    // Test Case: Load
    new_state.set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    new_state = context.update_def(&new_state, &mock_load).unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
}

#[test]
fn handling_stores() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");
    let rdi_reg = register("RDI");
    let mock_store = mock_store("store", variable_expr("R9"), variable_expr("RDI"));
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .pi_state
        .set_register(&r9_reg, setup.base_eight_offset.clone());

    pi_map.insert(Tid::new("store"), setup.pi_state.clone());
    setup.state.set_pointer_inference_map(pi_map.clone());

    let new_state = context.handle_store(
        setup.state,
        &mock_store,
        &variable_expr("R9"),
        &variable_expr("RDI"),
    );

    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state,),
        false
    );
}

#[test]
fn updating_def() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");
    let rdi_reg = register("RDI");
    let mock_assign_register = mock_assign("assign", "R9", variable_expr("RDI"));
    let mock_assign_stack = mock_assign("stack_assign", "R9", variable_expr("RSP"));
    let mock_load = mock_load("load", "R9", variable_expr("RDI"));
    let mock_store = mock_store("store", variable_expr("R9"), variable_expr("RDI"));
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results);
    context.current_sub = setup.project.program.term.subs.get(0);

    // Test Case: Assign R9 Register
    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    let mut new_state = context
        .update_def(&setup.state, &mock_assign_register)
        .unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );

    // Test Case: None State
    new_state.remove_all_register_taints();
    assert_eq!(context.update_def(&new_state, &mock_assign_register), None);

    // Test Case: Assign RSP Register
    pi_map.insert(Tid::new("stack_assign"), setup.pi_state.clone());
    new_state.set_pointer_inference_map(pi_map.clone());

    new_state.set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    new_state = context.update_def(&new_state, &mock_assign_stack).unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            Data::Pointer(PointerDomain::new(stack_id.clone(), bv(0))),
            &setup.pi_state
        ),
        true
    );

    // Test Case: Load
    new_state.set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    new_state = context.update_def(&new_state, &mock_load).unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );

    // Test Case: Store
    new_state.save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .pi_state
        .set_register(&r9_reg, setup.base_eight_offset.clone());
    new_state.set_pointer_inference_state_for_def(Some(setup.pi_state.clone()), &Tid::new("store"));
    new_state = context.update_def(&new_state, &mock_store).unwrap();

    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state,),
        false
    );
}

#[test]
fn updating_jumpsite() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    let mut new_state = context
        .update_jumpsite(
            &setup.state,
            &mock_jump("jump", "block2", "block1"),
            Some(&mock_jump("jump", "block2", "block1")),
            &Blk::mock(),
        )
        .unwrap();

    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();
    pi_map.insert(Tid::new("initial"), setup.pi_state);
    new_state.set_pointer_inference_map(pi_map);

    assert_eq!(
        new_state.get_register_taint(&r9_reg),
        Some(&Taint::Tainted(r9_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            setup.base_eight_offset,
            new_state
                .get_pointer_inference_state_at_def(&Tid::new("initial"))
                .unwrap()
        ),
        true
    );
}

#[test]
fn updating_callsite() {
    let mut setup = Setup::new();
    let mut return_state: Option<&State> = None;
    let mut target_state: Option<&State> = None;
    let jump_term = mock_jump("call_string", "sprintf", "block2");
    let r9_reg = register("R9");
    let rbp_reg = register("RBP");
    let rdi_reg = register("RDI");
    let rax_reg = register("RAX");

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    // Test Case: No return state
    assert_eq!(
        context.update_callsite(target_state, return_state, &jump_term, &jump_term),
        None
    );

    // Test Case: Return state but no target state
    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));

    let cloned_state = setup.state.clone();
    return_state = Some(&cloned_state);

    let mut new_state = context
        .update_callsite(target_state, return_state, &jump_term, &jump_term)
        .unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );

    // Test Case: Return and target state
    setup.state.remove_all_register_taints();
    setup
        .state
        .set_register_taint(&rdi_reg, Taint::Tainted(rdi_reg.size));

    setup
        .state
        .set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));

    target_state = Some(&setup.state);

    new_state = context
        .update_callsite(target_state, return_state, &jump_term, &jump_term)
        .unwrap();

    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(new_state.get_register_taint(&rax_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
}

#[test]
fn splitting_call_stub() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    let mut new_state = context.split_call_stub(&setup.state).unwrap();

    // Set pi_state to check for memory pointers
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();
    pi_map.insert(Tid::new("initial"), setup.pi_state);
    new_state.set_pointer_inference_map(pi_map);

    assert_eq!(
        new_state.get_register_taint(&r9_reg),
        Some(&Taint::Tainted(r9_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            setup.base_eight_offset,
            new_state
                .get_pointer_inference_state_at_def(&Tid::new("initial"))
                .unwrap()
        ),
        true
    );
}

#[test]
fn splitting_return_stub() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");
    let rax_reg = register("RAX");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    // Set pi_state to check for memory pointers
    let mut new_state = context.split_return_stub(&setup.state).unwrap();

    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();
    pi_map.insert(Tid::new("initial"), setup.pi_state);
    new_state.set_pointer_inference_map(pi_map);

    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rax_reg),
        Some(&Taint::Tainted(rax_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            setup.base_eight_offset,
            new_state
                .get_pointer_inference_state_at_def(&Tid::new("initial"))
                .unwrap()
        ),
        true
    );
}

#[test]
fn updating_call_stub() {
    let mut setup = Setup::new();
    let r9_reg = register("R9"); // non callee saved
    let rbp_reg = register("RBP"); // callee saved -> will point to RSP
    let rdi_reg = register("RDI"); // parameter 1 -> will point to RBP - 8
    let rsi_reg = register("RSI"); // parameter 2
    let mock_call = mock_jump("call_string", "sprintf", "block2");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .state
        .save_taint_to_memory(&setup.base_sixteen_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let mut string_symbols: HashMap<Tid, &ExternSymbol> = HashMap::new();
    let sprintf = &ExternSymbol::mock_string();
    string_symbols.insert(Tid::new("sprintf"), sprintf);

    let mut context = Context::mock(&setup.project, string_symbols, &pi_results);
    let current_sub = Sub::mock("func");
    context.current_sub = Some(&current_sub);

    let new_state = context.update_call_stub(&setup.state, &mock_call).unwrap();

    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state),
        true
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rsi_reg),
        Some(&Taint::Tainted(rsi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
}

#[test]
fn specializing_conditional() {
    let mut setup = Setup::new();
    let r9_reg = register("R9");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mut pi_results = PointerInferenceComputation::mock(&setup.project);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results);

    let mut new_state = context.split_call_stub(&setup.state).unwrap();

    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();
    pi_map.insert(Tid::new("initial"), setup.pi_state);
    new_state.set_pointer_inference_map(pi_map);

    assert_eq!(
        new_state.get_register_taint(&r9_reg),
        Some(&Taint::Tainted(r9_reg.size))
    );
    assert_eq!(
        new_state.check_if_address_points_to_taint(
            setup.base_eight_offset,
            new_state
                .get_pointer_inference_state_at_def(&Tid::new("initial"))
                .unwrap()
        ),
        true
    );
}
