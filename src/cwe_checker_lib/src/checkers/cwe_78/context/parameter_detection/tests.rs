use petgraph::graph::NodeIndex;

use crate::abstract_domain::{DataDomain, IntervalDomain, PointerDomain};
use crate::analysis::pointer_inference::{Data, PointerInference as PointerInferenceComputation};
use crate::intermediate_representation::{
    Arg, BinOpType, Bitvector, ByteSize, Expression, ExternSymbol, Tid, Variable,
};
use crate::utils::binary::RuntimeMemoryImage;
use crate::{checkers::cwe_476::Taint, utils::log::CweWarning};

use super::super::tests::{bv, Setup};
use super::Context;

use std::collections::{HashMap, HashSet};

impl<'a> Context<'a> {
    pub fn set_cwe_collector(&mut self, collector: crossbeam_channel::Sender<CweWarning>) {
        self.cwe_collector = collector;
    }
}

#[test]
fn tainting_generic_extern_symbol_parameters() {
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
    let string_sym = ExternSymbol::mock_string();
    string_syms.insert(Tid::new("sprintf"), &string_sym);
    let mut format_string_index: HashMap<String, usize> = HashMap::new();
    format_string_index.insert("sprintf".to_string(), 1);
    let context = Context::mock(
        &setup.project,
        string_syms,
        HashMap::new(),
        format_string_index,
        &pi_results,
        &mem_image,
    );
    let node_id = context
        .block_maps
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    // Test Case 1: String Symbol
    let mut new_state = context.taint_generic_extern_symbol_parameters(
        &setup.state,
        &ExternSymbol::mock_string(),
        node_id.clone(),
    );

    // Parameter
    assert_eq!(new_state.get_register_taint(&rdi_reg), None,);
    assert_eq!(new_state.get_register_taint(&rsi_reg), None,);
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
    new_state = context.taint_generic_extern_symbol_parameters(
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
fn tainting_extern_string_symbol_parameters() {
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
    let mut format_string_index: HashMap<String, usize> = HashMap::new();
    format_string_index.insert("sprintf".to_string(), 1);

    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        format_string_index,
        &pi_results,
        &mem_image,
    );
    let node_id = context
        .block_maps
        .jmp_to_blk_end_node_map
        .get(&(Tid::new("call_string"), Tid::new("func")))
        .unwrap();

    let new_state = context.taint_extern_string_symbol_parameters(
        &setup.state,
        &ExternSymbol::mock_string(),
        *node_id,
    );

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
}

#[test]
fn tainting_user_input_symbol_parameters() {
    let mut setup = Setup::new();

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded::<CweWarning>();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let call_source_node: NodeIndex = graph.node_indices().next().unwrap();
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();
    let mut format_string_index: HashMap<String, usize> = HashMap::new();
    format_string_index.insert("scanf".to_string(), 0);

    let global_address = Bitvector::from_str_radix(16, "500c").unwrap();
    let string_address =
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address));

    let mut pi_result_state = pi_results
        .get_node_value(call_source_node)
        .unwrap()
        .unwrap_value()
        .clone();

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    pi_result_state
        .write_to_address(
            &Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(Variable {
                    name: String::from("RSP"),
                    size: ByteSize::new(8),
                    is_temp: false,
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(0))),
            },
            &Data::Pointer(PointerDomain::new(setup.pi_state.stack_id.clone(), bv(-8))),
            &mem_image,
        )
        .expect("Failed to write to address.");

    pi_result_state.set_register(&Variable::mock("RDI", 8 as u64), string_address);

    pi_results.set_node_value(pi_result_state, call_source_node);

    let mut context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        format_string_index,
        &pi_results,
        &mem_image,
    );

    context.set_cwe_collector(cwe_sender);
    context.taint_source = Some(&setup.taint_source);
    context.taint_source_name = Some("system".to_string());

    context.taint_user_input_symbol_parameters(
        &setup.state,
        &ExternSymbol::mock_scanf(),
        call_source_node,
    );

    assert!(!cwe_receiver.is_empty());
}

#[test]
fn processing_scanf() {
    let mut setup = Setup::new();
    let string_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(8),
        data_type: None,
    };

    let (cwe_sender, cwe_receiver) = crossbeam_channel::unbounded::<CweWarning>();

    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let call_source_node: NodeIndex = graph.node_indices().next().unwrap();
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();

    let mut context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    context.set_cwe_collector(cwe_sender);
    context.taint_source = Some(&setup.taint_source);
    context.taint_source_name = Some("system".to_string());

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    setup
        .pi_state
        .write_to_address(
            &Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(Variable {
                    name: String::from("RSP"),
                    size: ByteSize::new(8),
                    is_temp: false,
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(0))),
            },
            &Data::Pointer(PointerDomain::new(setup.pi_state.stack_id.clone(), bv(-8))),
            context.runtime_memory_image,
        )
        .expect("Failed to write to address.");

    context.process_scanf(
        call_source_node,
        &mut setup.state,
        &setup.pi_state,
        vec![string_arg],
    );

    assert!(!cwe_receiver.is_empty());
}

#[test]
fn processing_sscanf() {
    let mut setup = Setup::new();
    let rdi_reg = Variable::mock("RDI", ByteSize::new(8));
    let string_arg = Arg::Stack {
        offset: 0,
        size: ByteSize::new(8),
        data_type: None,
    };

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

    setup
        .pi_state
        .set_register(&rdi_reg, setup.base_sixteen_offset.clone());

    setup
        .pi_state
        .write_to_address(
            &Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(Variable {
                    name: String::from("RSP"),
                    size: ByteSize::new(8),
                    is_temp: false,
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(0))),
            },
            &Data::Pointer(PointerDomain::new(setup.pi_state.stack_id.clone(), bv(-8))),
            context.runtime_memory_image,
        )
        .expect("Failed to write to address.");

    setup
        .state
        .save_taint_to_memory(&setup.base_eight_offset, Taint::Tainted(ByteSize::new(8)));

    context.process_sscanf(
        &mut setup.state,
        &setup.pi_state,
        vec![string_arg],
        &Arg::Register {
            var: rdi_reg,
            data_type: None,
        },
    );

    assert!(setup
        .state
        .address_points_to_taint(setup.base_sixteen_offset, &setup.pi_state));
    assert!(!setup
        .state
        .address_points_to_taint(setup.base_eight_offset, &setup.pi_state));
}

#[test]
fn tainting_function_arguments() {
    let mut setup = Setup::new();
    let rdi_reg = Variable::mock("RDI", 8);
    let args = vec![
        Arg::Register {
            var: rdi_reg.clone(),
            data_type: None,
        },
        Arg::Stack {
            offset: 24,
            size: ByteSize::from(8),
            data_type: None,
        },
    ];

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

    setup
        .pi_state
        .write_to_address(
            &Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(Variable {
                    name: String::from("RSP"),
                    size: ByteSize::new(8),
                    is_temp: false,
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(24))),
            },
            &Data::Pointer(PointerDomain::new(setup.pi_state.stack_id.clone(), bv(32))),
            context.runtime_memory_image,
        )
        .expect("Failed to write to address.");

    context.taint_function_parameters(&mut setup.state, &setup.pi_state, args);

    assert_eq!(
        setup.state.get_register_taint(&rdi_reg),
        Some(&Taint::Tainted(rdi_reg.size))
    );

    assert!(setup.state.address_points_to_taint(
        Data::Pointer(PointerDomain::new(setup.pi_state.stack_id.clone(), bv(32))),
        &setup.pi_state
    ));
}

#[test]
fn test_is_string_symbol() {
    let setup = Setup::new();
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();
    let mut string_symbol_map: HashMap<Tid, &ExternSymbol> = HashMap::new();
    let sprintf_symbol = ExternSymbol::mock_string();
    let mut memcpy_symbol = ExternSymbol::mock();
    memcpy_symbol.tid = Tid::new("memcpy");
    string_symbol_map.insert(Tid::new("sprintf"), &sprintf_symbol);
    let context = Context::mock(
        &setup.project,
        string_symbol_map,
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    assert!(context.is_string_symbol(&sprintf_symbol));
    assert!(!context.is_string_symbol(&memcpy_symbol));
}

#[test]
fn test_is_user_input_symbol() {
    let setup = Setup::new();
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();
    let mut user_input_symbol_map: HashMap<Tid, &ExternSymbol> = HashMap::new();
    let mut scanf_symbol = ExternSymbol::mock();
    scanf_symbol.tid = Tid::new("scanf");
    let mut memcpy_symbol = ExternSymbol::mock();
    memcpy_symbol.tid = Tid::new("memcpy");
    user_input_symbol_map.insert(Tid::new("scanf"), &scanf_symbol);
    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        user_input_symbol_map,
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    assert!(context.is_user_input_symbol(&scanf_symbol));
    assert!(!context.is_user_input_symbol(&memcpy_symbol));
}
