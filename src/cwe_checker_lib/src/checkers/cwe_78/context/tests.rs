use petgraph::visit::IntoNodeReferences;

use super::*;

use crate::analysis::{backward_interprocedural_fixpoint::Context as BackwardContext, graph::Node};
use crate::{
    abstract_domain::{DataDomain, PointerDomain, SizedDomain},
    analysis::pointer_inference::{Data, State as PointerInferenceState, ValueDomain},
    intermediate_representation::{Expression, Variable},
};

pub fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

impl ExternSymbol {
    pub fn mock_string() -> Self {
        ExternSymbol {
            tid: Tid::new("sprintf"),
            addresses: vec!["UNKNOWN".to_string()],
            name: "sprintf".to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI", 8), Arg::mock_register("RSI", 8)],
            return_values: vec![Arg::mock_register("RAX", 8)],
            no_return: false,
            has_var_args: true,
        }
    }

    pub fn mock_scanf() -> Self {
        ExternSymbol {
            tid: Tid::new("scanf"),
            addresses: vec!["UNKNOWN".to_string()],
            name: "scanf".to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI", 8)],
            return_values: vec![Arg::mock_register("RAX", 8)],
            no_return: false,
            has_var_args: true,
        }
    }

    pub fn mock_sscanf() -> Self {
        ExternSymbol {
            tid: Tid::new("sscanf"),
            addresses: vec!["UNKNOWN".to_string()],
            name: "sscanf".to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI", 8), Arg::mock_register("RSI", 8)],
            return_values: vec![Arg::mock_register("RAX", 8)],
            no_return: false,
            has_var_args: true,
        }
    }
}
pub struct Setup {
    pub project: Project,
    pub state: State,
    pub pi_state: PointerInferenceState,
    pub taint_source: Term<Jmp>,
    pub base_eight_offset: DataDomain<ValueDomain>,
    pub base_sixteen_offset: DataDomain<ValueDomain>,
}

impl Setup {
    pub fn new() -> Self {
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
        let mut block1 = Blk::mock_with_tid("block1");
        let block2 = Blk::mock_with_tid("block2");
        let def1 = Def::assign(
            "def1",
            Variable::mock("RBP", 8 as u64),
            Expression::var("RSP", 8),
        );
        let def2 = Def::assign(
            "def2",
            Variable::mock("RDI", 8 as u64),
            Expression::var("RBP", 8).plus_const(-8),
        );
        let def3 = Def::assign(
            "def3",
            Variable::mock("RSI", 8 as u64),
            Expression::Const(Bitvector::from_str_radix(16, "3002").unwrap()),
        );
        let jump = Jmp::call("call_string", "sprintf", Some("block2"));
        block1.term.defs.push(def1);
        block1.term.defs.push(def2);
        block1.term.defs.push(def3);
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
            taint_source,
            base_eight_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-8))),
            base_sixteen_offset: Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-16))),
        }
    }
}

impl<'a> Context<'a> {
    pub fn mock(
        project: &'a Project,
        string_symbols: HashMap<Tid, &'a ExternSymbol>,
        user_input_symbols: HashMap<Tid, &'a ExternSymbol>,
        format_string_index: HashMap<String, usize>,
        pi_results: &'a PointerInferenceComputation<'a>,
        mem_image: &'a RuntimeMemoryImage,
    ) -> Self {
        let (cwe_sender, _) = crossbeam_channel::unbounded();
        let mut graph = pi_results.get_graph().clone();
        graph.reverse();

        let mut extern_symbol_map = HashMap::new();
        for symbol in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(symbol.tid.clone(), symbol);
        }

        let mut block_first_def_set: HashSet<(Tid, Tid)> = HashSet::new();
        let mut block_start_last_def_map = HashMap::new();
        let mut jmp_to_blk_end_node_map = HashMap::new();
        for (node_id, node) in graph.node_references() {
            match node {
                Node::BlkStart(block, sub) => match block.term.defs.len() {
                    0 => (),
                    num_of_defs => {
                        let first_def = block.term.defs.get(0).unwrap();
                        let last_def = block.term.defs.get(num_of_defs - 1).unwrap();
                        block_first_def_set.insert((first_def.tid.clone(), sub.tid.clone()));
                        block_start_last_def_map
                            .insert((last_def.tid.clone(), sub.tid.clone()), node_id);
                    }
                },
                Node::BlkEnd(block, sub) => {
                    for jmp in block.term.jmps.iter() {
                        jmp_to_blk_end_node_map.insert((jmp.tid.clone(), sub.tid.clone()), node_id);
                    }
                }
                _ => (),
            }
        }

        let block_maps: BlockMaps = BlockMaps {
            block_first_def_set,
            block_start_last_def_map,
            jmp_to_blk_end_node_map,
        };

        let symbol_maps: SymbolMaps = SymbolMaps {
            string_symbol_map: string_symbols,
            user_input_symbol_map: user_input_symbols,
            extern_symbol_map,
            format_string_index,
        };

        Context::new(
            project,
            mem_image,
            std::sync::Arc::new(graph),
            pi_results,
            std::sync::Arc::new(symbol_maps),
            std::sync::Arc::new(block_maps),
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
    let mut context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    context.set_taint_source(&setup.taint_source, &String::from("system"), &current_sub);
    assert_eq!(context.taint_source, Some(&setup.taint_source));
    assert_eq!(context.taint_source_name, Some(String::from("system")));
    assert_eq!(context.taint_source_sub, Some(&current_sub));
}

#[test]
fn adding_temporary_callee_saved_register_taints_to_mem_taints() {
    let mut setup = Setup::new();
    let rbp_reg = Variable::mock("RBP", 8 as u64);
    let rcx_reg = Variable::mock("RCX", 8 as u64);
    setup
        .pi_state
        .set_register(&rbp_reg, setup.base_eight_offset.clone());
    setup
        .pi_state
        .set_register(&rcx_reg, setup.base_sixteen_offset.clone());
    setup
        .state
        .set_register_taint(&rbp_reg, Taint::Tainted(rbp_reg.size));
    setup
        .state
        .set_register_taint(&rcx_reg, Taint::Tainted(rcx_reg.size));

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    let result = context.add_temporary_callee_saved_register_taints_to_mem_taints(
        &setup.pi_state,
        &mut setup.state,
    );

    assert!(result.len() == 1);
    assert!(setup
        .state
        .address_points_to_taint(result.get(0).unwrap().clone(), &setup.pi_state))
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    let arg = Arg::Register {
        var: rdi_reg,
        data_type: None,
    };
    assert_eq!(
        context.first_param_points_to_memory_taint(&setup.pi_state, &mut setup.state, &arg),
        true
    );
    assert_eq!(
        setup
            .state
            .address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
}

#[test]
fn creating_pi_def_map() {
    let setup = Setup::new();
    let rsi_reg = Variable::mock("RSI", 8 as u64);
    let rdi_reg = Variable::mock("RDI", 8 as u64);
    let def1 = Tid::new("def1");
    let def2 = Tid::new("def2");
    let def3 = Tid::new("def3");

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    let start_node = context
        .block_maps
        .block_start_last_def_map
        .get(&(def3.clone(), current_sub.tid.clone()))
        .unwrap();

    let pi_def_map = context.create_pi_def_map(start_node.clone()).unwrap();

    for (def_tid, pi_state) in pi_def_map.iter() {
        if *def_tid == def1 {
            assert_eq!(pi_state.get_register(&rsi_reg), Data::new_top(rsi_reg.size));
        } else if *def_tid == def2 {
            assert_eq!(
                pi_state.get_register(&rdi_reg),
                Data::Pointer(PointerDomain::new(stack_id.clone(), bv(-8))),
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
        Expression::var("RSP", 8),
    );
    let def2 = Def::assign(
        "def2",
        Variable::mock("RDI", 8 as u64),
        Expression::var("RBP", 8).plus_const(-8),
    );

    let def3 = Def::assign(
        "def3",
        Variable::mock("RDI", 8 as u64),
        Expression::Const(Bitvector::from_str_radix(16, "3002").unwrap()),
    );

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

    let start_node = context
        .block_maps
        .block_start_last_def_map
        .get(&(def3.tid.clone(), current_sub.tid.clone()))
        .unwrap();

    assert_eq!(
        context.get_blk_start_node_if_last_def(&setup.state, &def1),
        None
    );
    assert_eq!(
        context.get_blk_start_node_if_last_def(&setup.state, &def2),
        None
    );
    assert_eq!(
        context.get_blk_start_node_if_last_def(&setup.state, &def3),
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );
    let current_sub = setup.project.program.term.subs.get(0).unwrap();
    setup.state.set_current_sub(current_sub);

    let blk_end_node_id = context
        .block_maps
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

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
        Expression::var("RDI", 8),
    );
    let mock_assign_stack = Def::assign(
        "stack_assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RSP", 8),
    );
    let mock_load = Def::load(
        "load",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI", 8),
    );
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );
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
        new_state.address_points_to_taint(
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
        Expression::var("RDI", 8),
    );
    let mock_assign_stack = Def::assign(
        "stack_assign",
        Variable::mock("R9", 8 as u64),
        Expression::var("RSP", 8),
    );
    let mock_load = Def::load(
        "load",
        Variable::mock("R9", 8 as u64),
        Expression::var("RDI", 8),
    );
    let mock_store = Def::store("store", Expression::var("R9", 8), Expression::var("RDI", 8));
    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();

    let stack_id = setup.pi_state.stack_id.clone();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );
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
        new_state.address_points_to_taint(
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
        new_state.address_points_to_taint(setup.base_eight_offset, &setup.pi_state,),
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

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
        new_state.address_points_to_taint(
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

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
        new_state.address_points_to_taint(
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

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
        new_state.address_points_to_taint(
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
    setup.project.calling_conventions = vec![CallingConvention::mock_with_parameter_registers(
        vec!["RDI".to_string(), "RSI".to_string()],
        vec!["XMM0".to_string()],
    )];
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
    let mut format_string_index: HashMap<String, usize> = HashMap::new();
    format_string_index.insert("sprintf".to_string(), 1);

    let context = Context::mock(
        &setup.project,
        string_symbols,
        HashMap::new(),
        format_string_index,
        &pi_results,
        &mem_image,
    );
    let current_sub = Sub::mock("func");
    setup.state.set_current_sub(&current_sub);

    let new_state = context.update_call_stub(&setup.state, &mock_call).unwrap();

    assert_eq!(
        new_state.address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state),
        true
    );
    assert_eq!(
        new_state.address_points_to_taint(setup.base_eight_offset, &setup.pi_state),
        false
    );
    assert_eq!(new_state.get_register_taint(&rdi_reg), None,);
    assert_eq!(new_state.get_register_taint(&rsi_reg), None,);
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

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    let mut new_state = context.split_call_stub(&setup.state).unwrap();

    let mut pi_map: HashMap<Tid, PointerInferenceState> = HashMap::new();
    pi_map.insert(Tid::new("initial"), setup.pi_state);
    new_state.set_pointer_inference_map(pi_map);

    assert_eq!(
        new_state.get_register_taint(&r9_reg),
        Some(&Taint::Tainted(r9_reg.size))
    );
    assert_eq!(
        new_state.address_points_to_taint(
            setup.base_eight_offset,
            new_state
                .get_pointer_inference_state_at_def(&Tid::new("initial"))
                .unwrap()
        ),
        true
    );
}
