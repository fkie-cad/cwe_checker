use crate::intermediate_representation::{Bitvector, Tid};

use super::*;

fn mock_pi_state() -> PointerInferenceState {
    PointerInferenceState::new(&Variable::mock("RSP", 8 as u64), Tid::new("func"))
}

#[test]
fn test_get_return_registers_from_symbol() {
    assert_eq!(
        vec!["RAX"],
        get_return_registers_from_symbol(&ExternSymbol::mock_string())
    );
}

#[test]
fn test_get_variable_parameters() {
    let mem_image = RuntimeMemoryImage::mock();
    let mut pi_state = mock_pi_state();
    let sprintf_symbol = ExternSymbol::mock_string();
    let mut format_string_index_map: HashMap<String, usize> = HashMap::new();
    format_string_index_map.insert("sprintf".to_string(), 0);
    let global_address = Bitvector::from_str_radix(16, "5000").unwrap();
    pi_state.set_register(
        &Variable::mock("RDI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );
    let mut project = Project::mock_empty();
    let cconv = CallingConvention::mock_with_parameter_registers(
        vec!["RDI".to_string()],
        vec!["XMM0".to_string()],
    );
    project.calling_conventions = vec![cconv];

    let mut output: Vec<Arg> = Vec::new();
    output.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Char),
    });

    output.push(Arg::Stack {
        offset: 4,
        size: ByteSize::new(4),
        data_type: Some(Datatype::Integer),
    });
    assert_eq!(
        output,
        get_variable_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
            &mem_image,
        )
        .unwrap()
    );

    output = vec![Arg::Stack {
        offset: 0,
        size: ByteSize::new(8),
        data_type: Some(Datatype::Pointer),
    }];

    let global_address = Bitvector::from_str_radix(16, "500c").unwrap();
    pi_state.set_register(
        &Variable::mock("RDI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    assert_eq!(
        output,
        get_variable_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
            &mem_image,
        )
        .unwrap()
    );
}

#[test]
fn test_get_input_format_string() {
    let mem_image = RuntimeMemoryImage::mock();
    let mut pi_state = mock_pi_state();
    let sprintf_symbol = ExternSymbol::mock_string();

    let global_address = Bitvector::from_str_radix(16, "3002").unwrap();
    pi_state.set_register(
        &Variable::mock("RSI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    assert_eq!(
        "Hello World",
        get_input_format_string(
            &pi_state,
            &sprintf_symbol,
            1,
            &Variable::mock("RSP", 8 as u64),
            &mem_image
        )
        .unwrap()
    );
}

#[test]
fn test_parse_format_string_destination_and_return_content() {
    let mem_image = RuntimeMemoryImage::mock();
    let string_address_vector = Bitvector::from_str_radix(16, "3002").unwrap();
    let string_address = IntervalDomain::new(string_address_vector.clone(), string_address_vector);

    assert_eq!(
        "Hello World",
        parse_format_string_destination_and_return_content(string_address, &mem_image).unwrap()
    );
}

#[test]
fn test_parse_format_string_parameters() {
    let test_cases: Vec<&str> = vec![
        "%s \"%s\" %s",
        "ifconfig eth0 add 3ffe:501:ffff:101:2%02x:%02xff:fe%02x:%02x%02x/64",
        "/dev/sd%c%d",
        "%s: Unable to open \'%s\', errno=%d\n",
        "%s %lli",
    ];
    let properties = DatatypeProperties::mock();
    let expected_outputs: Vec<Vec<(Datatype, ByteSize)>> = vec![
        vec![
            (Datatype::from("s".to_string()), properties.pointer_size),
            (Datatype::from("s".to_string()), properties.pointer_size),
            (Datatype::from("s".to_string()), properties.pointer_size),
        ],
        vec![
            (Datatype::from("x".to_string()), properties.integer_size),
            (Datatype::from("x".to_string()), properties.integer_size),
            (Datatype::from("x".to_string()), properties.integer_size),
            (Datatype::from("x".to_string()), properties.integer_size),
            (Datatype::from("x".to_string()), properties.integer_size),
        ],
        vec![
            (Datatype::from("c".to_string()), properties.integer_size),
            (Datatype::from("d".to_string()), properties.integer_size),
        ],
        vec![
            (Datatype::from("s".to_string()), properties.pointer_size),
            (Datatype::from("s".to_string()), properties.pointer_size),
            (Datatype::from("d".to_string()), properties.integer_size),
        ],
        vec![
            (Datatype::from("s".to_string()), properties.pointer_size),
            (Datatype::from("lli".to_string()), properties.pointer_size),
        ],
    ];

    for (index, (case, output)) in test_cases
        .into_iter()
        .zip(expected_outputs.into_iter())
        .enumerate()
    {
        if index == 4 {
            assert_ne!(
                output,
                parse_format_string_parameters(case, &properties).unwrap_or(vec![])
            );
        } else {
            assert_eq!(
                output,
                parse_format_string_parameters(case, &properties).unwrap()
            );
        }
    }
}

#[test]
fn test_calculate_parameter_locations() {
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
    let mut parameters: Vec<(Datatype, ByteSize)> = Vec::new();
    parameters.push(("d".to_string().into(), ByteSize::new(8)));
    parameters.push(("f".to_string().into(), ByteSize::new(16)));
    parameters.push(("s".to_string().into(), ByteSize::new(8)));

    let mut expected_args = vec![
        Arg::Register {
            var: Variable::mock("R8", ByteSize::new(8)),
            data_type: Some(Datatype::Integer),
        },
        Arg::Register {
            var: Variable::mock("XMM0", ByteSize::new(16)),
            data_type: Some(Datatype::Double),
        },
        Arg::Register {
            var: Variable::mock("R9", ByteSize::new(8)),
            data_type: Some(Datatype::Pointer),
        },
    ];

    // Test Case 1: The string parameter is still written in the R9 register since 'f' is contained in the float register.
    assert_eq!(
        expected_args,
        calculate_parameter_locations(parameters.clone(), &cconv, format_string_index)
    );

    parameters.push(("s".to_string().into(), ByteSize::new(8)));
    expected_args.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(8),
        data_type: Some(Datatype::Pointer),
    });

    // Test Case 2: A second string parameter does not fit into the registers anymore and is written into the stack.
    assert_eq!(
        expected_args,
        calculate_parameter_locations(parameters, &cconv, format_string_index)
    );
}

#[test]
fn test_create_stack_arg() {
    assert_eq!(
        Arg::Stack {
            size: ByteSize::new(8),
            offset: 8,
            data_type: Some(Datatype::Pointer),
        },
        create_stack_arg(ByteSize::new(8), 8, Datatype::Pointer),
    )
}

#[test]
fn test_create_register_arg() {
    assert_eq!(
        Arg::Register {
            var: Variable::mock("R9", ByteSize::new(8)),
            data_type: Some(Datatype::Pointer),
        },
        create_register_arg(ByteSize::new(8), "R9".to_string(), Datatype::Pointer),
    );
}
