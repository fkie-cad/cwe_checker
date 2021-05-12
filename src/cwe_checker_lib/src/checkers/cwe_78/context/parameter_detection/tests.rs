use crate::checkers::cwe_476::Taint;
use crate::intermediate_representation::{
    Arg, BinOpType, Bitvector, ByteSize, Expression, ExternSymbol, Tid, Variable,
};
use crate::utils::binary::RuntimeMemoryImage;
use crate::{
    abstract_domain::{DataDomain, IntervalDomain, PointerDomain},
    intermediate_representation::CallingConvention,
};
use crate::{
    analysis::pointer_inference::{Data, PointerInference as PointerInferenceComputation},
    intermediate_representation::DatatypeProperties,
};

use super::super::tests::{bv, Setup};
use super::Context;

use std::collections::{HashMap, HashSet};

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
    string_syms.insert(Tid::new("sprintf"), &setup.string_sym);
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

    // TODO: add test for scanf when parameter detection is implemented
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

    let new_state =
        context.taint_extern_string_symbol_parameters(&setup.state, &setup.string_sym, *node_id);

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
fn tainting_function_arguments() {
    let mut setup = Setup::new();
    let rdi_reg = Variable::mock("RDI", 8);
    let args = vec![
        Arg::Register(rdi_reg.clone()),
        Arg::Stack {
            offset: 24,
            size: ByteSize::from(8),
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
fn test_get_return_registers_from_symbol() {
    assert_eq!(
        vec!["RAX"],
        Context::get_return_registers_from_symbol(&ExternSymbol::mock_string())
    );
}

#[test]
fn test_get_input_format_string() {
    let mut setup = Setup::new();
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();
    let sprintf_symbol = ExternSymbol::mock_string();
    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        &pi_results,
        &mem_image,
    );

    let global_address = Bitvector::from_str_radix(16, "3002").unwrap();
    setup.pi_state.set_register(
        &Variable::mock("RSI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    assert_eq!(
        "Hello World",
        context.get_input_format_string(&setup.pi_state, &sprintf_symbol, 1)
    );
}

#[test]
fn test_parse_format_string_destination_and_return_content() {
    let setup = Setup::new();
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

    // Test Case 2: Global memory location contains string itself.
    let string_address_vector = Bitvector::from_str_radix(16, "3002").unwrap();
    let string_address = DataDomain::Value(IntervalDomain::new(
        string_address_vector.clone(),
        string_address_vector,
    ));

    assert_eq!(
        "Hello World",
        context.parse_format_string_destination_and_return_content(string_address)
    );
}

#[test]
fn test_parse_format_string_parameter() {
    let setup = Setup::new();
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
    let test_cases: Vec<&str> = vec![
        "%s \"%s\" %s",
        "ifconfig eth0 add 3ffe:501:ffff:101:2%02x:%02xff:fe%02x:%02x%02x/64",
        "/dev/sd%c%d",
        "%s: Unable to open \'%s\', errno=%d\n",
    ];
    let properties = DatatypeProperties::mock();
    let expected_outputs: Vec<Vec<(String, ByteSize)>> = vec![
        vec![
            ("s".to_string(), properties.pointer_size),
            ("s".to_string(), properties.pointer_size),
            ("s".to_string(), properties.pointer_size),
        ],
        vec![
            ("x".to_string(), properties.integer_size),
            ("x".to_string(), properties.integer_size),
            ("x".to_string(), properties.integer_size),
            ("x".to_string(), properties.integer_size),
            ("x".to_string(), properties.integer_size),
        ],
        vec![
            ("c".to_string(), properties.integer_size),
            ("d".to_string(), properties.integer_size),
        ],
        vec![
            ("s".to_string(), properties.pointer_size),
            ("s".to_string(), properties.pointer_size),
            ("d".to_string(), properties.integer_size),
        ],
    ];

    for (case, output) in test_cases.into_iter().zip(expected_outputs.into_iter()) {
        assert_eq!(output, context.parse_format_string_parameters(case));
    }
}

#[test]
fn test_map_format_specifier_to_bytesize() {
    let setup = Setup::new();
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

    assert_eq!(
        ByteSize::new(4),
        context.map_format_specifier_to_bytesize("s".to_string())
    );
    assert_eq!(
        ByteSize::new(8),
        context.map_format_specifier_to_bytesize("f".to_string())
    );
    assert_eq!(
        ByteSize::new(4),
        context.map_format_specifier_to_bytesize("d".to_string())
    );
}

#[test]
#[should_panic]
fn test_map_invalid_format_specifier_to_bytesize() {
    let setup = Setup::new();
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

    context.map_format_specifier_to_bytesize("w".to_string());
}

#[test]
fn test_get_variable_number_parameters() {
    let mut setup = Setup::new();
    let mem_image = RuntimeMemoryImage::mock();
    let graph = crate::analysis::graph::get_program_cfg(&setup.project.program, HashSet::new());
    let mut pi_results = PointerInferenceComputation::mock(&setup.project, &mem_image, &graph);
    pi_results.compute();
    let sprintf_symbol = ExternSymbol::mock_string();
    let mut format_string_index: HashMap<String, usize> = HashMap::new();
    format_string_index.insert("sprintf".to_string(), 0);
    let context = Context::mock(
        &setup.project,
        HashMap::new(),
        HashMap::new(),
        format_string_index,
        &pi_results,
        &mem_image,
    );

    let global_address = Bitvector::from_str_radix(16, "5000").unwrap();
    setup.pi_state.set_register(
        &Variable::mock("RDI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    let mut output: Vec<Arg> = Vec::new();
    assert_eq!(
        output,
        context.get_variable_number_parameters(&setup.pi_state, &sprintf_symbol)
    );

    output.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
    });

    let global_address = Bitvector::from_str_radix(16, "500c").unwrap();
    setup.pi_state.set_register(
        &Variable::mock("RDI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    assert_eq!(
        output,
        context.get_variable_number_parameters(&setup.pi_state, &sprintf_symbol)
    );
}

#[test]
fn test_calculate_parameter_locations() {
    let setup = Setup::new();
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
    let cconv = CallingConvention::mock_with_parameter_registers(
        vec![
            "RDI".to_string(),
            "RSI".to_string(),
            "R8".to_string(),
            "R9".to_string(),
        ],
        vec!["XMM0".to_string()],
    );
    let format_string_index: usize = 1;
    let mut parameters: Vec<(String, ByteSize)> = Vec::new();
    parameters.push(("d".to_string(), ByteSize::new(4)));
    parameters.push(("f".to_string(), ByteSize::new(8)));
    parameters.push(("s".to_string(), ByteSize::new(4)));

    let mut expected_args = vec![Arg::Register(Variable::mock("R9", ByteSize::new(8)))];

    // Test Case 1: The string parameter is still written in the R9 register since 'f' is contained in the float register.
    assert_eq!(
        expected_args,
        context.calculate_parameter_locations(parameters.clone(), &cconv, format_string_index)
    );

    parameters.push(("s".to_string(), ByteSize::new(4)));
    expected_args.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
    });

    // Test Case 2: A second string parameter does not fit into the registers anymore and is written into the stack.
    assert_eq!(
        expected_args,
        context.calculate_parameter_locations(parameters, &cconv, format_string_index)
    );
}

#[test]
fn test_create_string_stack_arg() {
    assert_eq!(
        Arg::Stack {
            size: ByteSize::new(8),
            offset: 8,
        },
        Context::create_string_stack_arg(ByteSize::new(8), 8),
    )
}

#[test]
fn test_create_string_register_arg() {
    assert_eq!(
        Arg::Register(Variable::mock("R9", ByteSize::new(8))),
        Context::create_string_register_arg(ByteSize::new(8), "R9".to_string()),
    );
}

#[test]
fn test_is_integer() {
    assert!(Context::is_integer("d"));
    assert!(Context::is_integer("i"));
    assert!(!Context::is_integer("f"));
}

#[test]
fn test_is_pointer() {
    assert!(Context::is_pointer("s"));
    assert!(Context::is_pointer("S"));
    assert!(Context::is_pointer("n"));
    assert!(Context::is_pointer("p"));
    assert!(!Context::is_pointer("g"));
}

#[test]
fn test_is_float() {
    assert!(Context::is_float("f"));
    assert!(Context::is_float("A"));
    assert!(!Context::is_float("s"));
}

#[test]
fn test_is_string() {
    assert!(Context::is_string("s"));
    assert!(Context::is_string("S"));
    assert!(!Context::is_string("g"));
}
