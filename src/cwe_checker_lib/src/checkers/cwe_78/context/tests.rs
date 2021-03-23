use super::*;

use crate::analysis::backward_interprocedural_fixpoint::Context as BackwardContext;
use crate::{
    abstract_domain::{DataDomain, PointerDomain, SizedDomain},
    analysis::pointer_inference::{Data, State as PointerInferenceState, ValueDomain},
    intermediate_representation::{Expression, Variable},
};

// TODO: change actual mock function for blocks to receive a TID parameter and then remove this function
fn mock_block(tid: &str) -> Term<Blk> {
    Term {
        tid: Tid::new(tid),
        term: Blk {
            defs: Vec::new(),
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    }
}

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

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
struct Setup {
    project: Project,
    state: State,
    pi_state: PointerInferenceState,
    string_sym: ExternSymbol,
    taint_source: Term<Jmp>,
    base_eight_offset: DataDomain<ValueDomain>,
    base_sixteen_offset: DataDomain<ValueDomain>,
}

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
        let def1 = Def::assign(
            "def1",
            Variable::mock("RBP", 8 as u64),
            Expression::var("RSP"),
        );
        let def2 = Def::assign(
            "def2",
            Variable::mock("RDI", 8 as u64),
            Expression::var("RBP").plus_const(-8),
        );
        let jump = Jmp::call("call_string", "sprintf", Some("block2"));
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

impl<'a> Context<'a> {
    fn mock(
        project: &'a Project,
        string_symbols: HashMap<Tid, &'a ExternSymbol>,
        pi_results: &'a PointerInferenceComputation<'a>,
        mem_image: &'a RuntimeMemoryImage,
    ) -> Self {
        let (cwe_sender, _) = crossbeam_channel::unbounded();
        Context::new(
            project,
            mem_image,
            pi_results,
            string_symbols,
            HashMap::new(),
            cwe_sender,
        )
    }
}

#[test]
fn setting_taint_source() {
    let setup = Setup::new();
    let current_sub = Sub::mock("func");

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    let mem_image = RuntimeMemoryImage::mock();
    let mut context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    context.set_taint_source(&setup.taint_source, &String::from("system"), &current_sub);
    assert_eq!(context.taint_source, Some(&setup.taint_source));
    assert_eq!(context.taint_source_name, Some(String::from("system")));
    assert_eq!(context.taint_source_sub, Some(&current_sub));
}

#[test]
fn tainting_string_function_parameters() {
    let mut setup = Setup::new();
    let rbp_reg = Variable::mock("RBP", 8 as u64); // callee saved -> will point to RSP
    let rdi_reg = Variable::mock("RDI", 8 as u64); // parameter 1 -> will point to RBP - 8
    let rsi_reg = Variable::mock("RSI", 8 as u64); // parameter 2

    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .state
        .save_taint_to_memory(&setup.base_sixteen_offset, Taint::Tainted(ByteSize::new(8)));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
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
fn first_param_pointing_to_memory_taint() {
    let mut setup = Setup::new();

    let rdi_reg = Variable::mock("RDI", 8 as u64);
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));
    setup
        .pi_state
        .set_register(&rdi_reg, setup.base_eight_offset.clone());

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    let arg = Arg::Register(rdi_reg);
    assert_eq!(
        context.first_param_points_to_memory_taint(&setup.pi_state, &mut setup.state, &arg),
        true
    );
    assert_eq!(
        setup
            .state
            .check_if_address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
}

#[test]
fn tainting_generic_function_parameters_and_removing_non_callee_saved() {
    let mut setup = Setup::new();
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rbp_reg = Variable::mock("RBP", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let rsi_reg = Variable::mock("RSI", 8 as u64);
    let rax_reg = Variable::mock("RAX", 8 as u64);

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
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
    let context = Context::mock(&setup.project, string_syms, &pi_results, &mem_image);
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

    // TODO: add test for scanf when parameter detection is implemented
}

#[test]
fn tainting_stack_parameters() {
    let setup = Setup::new();
    let offset = 4 as i64;
    let size = ByteSize::new(8);

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
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
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let rsi_reg = Variable::mock("RSI", 8 as u64);
    let params = vec![
        Arg::Register(rdi_reg.clone()),
        Arg::Register(rsi_reg.clone()),
        Arg::Stack {
            offset: 4,
            size: ByteSize::new(8),
        },
    ];

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
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
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let def1 = Tid::new("def1");
    let def2 = Tid::new("def2");

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    let start_node = context
        .block_start_last_def_map
        .get(&(def2.clone(), current_sub.tid.clone()))
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
    let mut setup = Setup::new();
    let def1 = Def::assign(
        "def1",
        Variable::mock("RBP", 8 as u64),
        Expression::var("RSP"),
    );
    let def2 = Def::assign(
        "def2",
        Variable::mock("RDI", 8 as u64),
        Expression::var("RBP").plus_const(-8),
    );

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

    let start_node = context
        .block_start_last_def_map
        .get(&(def2.tid.clone(), current_sub.tid.clone()))
        .unwrap();

    assert_eq!(
        context.get_blk_start_node_if_last_def(&setup.state, &def1),
        None
    );
    assert_eq!(
        context.get_blk_start_node_if_last_def(&setup.state, &def2),
        Some(start_node.clone())
    );
}

#[test]
fn getting_source_node() {
    let mut setup = Setup::new();
    let call_tid = Tid::new("call_string");

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

    let blk_end_node_id = context
        .jmp_to_blk_end_node_map
        .get(&(call_tid.clone(), current_sub.tid.clone()))
        .unwrap();

    assert_eq!(
        context.get_source_node(&setup.state, &call_tid),
        *blk_end_node_id
    );
}

#[test]
fn updating_target_state_for_callsite() {
    let mut setup = Setup::new();
    let caller_sub = Sub::mock("caller");
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rbp_reg = Variable::mock("RBP", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    let mut return_state = setup.state.clone();

    // Test Case 1: No target state
    assert_eq!(
        context.update_target_state_for_callsite(None, None, &caller_sub),
        None
    );

    // Test Case 2: Target state but no return state
    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));

    setup
        .state
        .set_register_taint(&rdi_reg, Taint::Tainted(rdi_reg.size));

    let new_state = context
        .update_target_state_for_callsite(None, Some(&setup.state), &caller_sub)
        .unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );

    assert_eq!(*new_state.get_current_sub().as_ref().unwrap(), caller_sub);

    // Test Case 3: Target state and return state
    return_state.set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));
    let new_state = context
        .update_target_state_for_callsite(Some(&return_state), Some(&setup.state), &caller_sub)
        .unwrap();
    assert_eq!(new_state.get_register_taint(&r9_reg), None);
    assert_eq!(
        new_state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );
    assert_eq!(
        new_state.get_register_taint(&rbp_reg),
        Some(&Taint::Tainted(rbp_reg.size))
    );

    assert_eq!(*new_state.get_current_sub().as_ref().unwrap(), caller_sub);
}

#[test]
fn handling_assign_and_load() {
    let mut setup = Setup::new();
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let mock_assign_register = Def::assign(
        "assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI"),
    );
    let mock_assign_stack = Def::assign(
        "stack_assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RSP"),
    );
    let mock_load = Def::load(
        "load",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI"),
    );
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

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
fn updating_def() {
    let mut setup = Setup::new();
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let mock_assign_register = Def::assign(
        "assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI"),
    );
    let mock_assign_stack = Def::assign(
        "stack_assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RSP"),
    );
    let mock_load = Def::load(
        "load",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI"),
    );
    let mock_store = Def::store("store", Expression::var("R9"), Expression::var("RDI"));
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

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
    let r9_reg = Variable::mock("R9", 8 as u64);

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    let mut new_state = context
        .update_jumpsite(
            &setup.state,
            &Jmp::branch("jump", "block2"),
            Some(&Jmp::branch("jump", "block2")),
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
    let jump_term = Jmp::call("call_string", "sprintf", Some("block2"));
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rbp_reg = Variable::mock("RBP", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let rax_reg = Variable::mock("RAX", 8 as u64);
    let caller_sub = Sub::mock("caller");

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    // Test Case: No return state
    assert_eq!(
        context.update_callsite(
            target_state,
            return_state,
            &caller_sub,
            &jump_term,
            &jump_term
        ),
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
        .update_callsite(
            target_state,
            return_state,
            &caller_sub,
            &jump_term,
            &jump_term,
        )
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
        .update_callsite(
            target_state,
            return_state,
            &caller_sub,
            &jump_term,
            &jump_term,
        )
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
    let r9_reg = Variable::mock("R9", 8 as u64);

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

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
    let r9_reg = Variable::mock("R9", 8 as u64);
    let rax_reg = Variable::mock("RAX", 8 as u64);
    let called_sub = Sub::mock("called");

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .set_register_taint(&rax_reg, Taint::Tainted(rax_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

    // Set pi_state to check for memory pointers
    let mut new_state = context
        .split_return_stub(&setup.state, &called_sub)
        .unwrap();

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
    let r9_reg = Variable::mock("R9", 8 as u64); // non callee saved
    let rbp_reg = Variable::mock("RBP", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let rsi_reg = Variable::mock("RSI", 8 as u64);
    let mock_call = Jmp::call("call_string", "sprintf", Some("block2"));

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

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let mut string_symbols: HashMap<Tid, &ExternSymbol> = HashMap::new();
    let sprintf = &ExternSymbol::mock_string();
    string_symbols.insert(Tid::new("sprintf"), sprintf);

    let context = Context::mock(&setup.project, string_symbols, &pi_results, &mem_image);
    let current_sub = Sub::mock("func");
    setup.state.set_current_sub(&current_sub);

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
    let r9_reg = Variable::mock("R9", 8 as u64);

    setup
        .state
        .set_register_taint(&r9_reg, Taint::Tainted(r9_reg.size));
    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(&setup.project, HashMap::new(), &pi_results, &mem_image);

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
