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
fn test_get_variable_number_parameters() {
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
    assert_eq!(
        output,
        get_variable_number_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
            &mem_image,
        )
    );

    output.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(8),
    });

    let global_address = Bitvector::from_str_radix(16, "500c").unwrap();
    pi_state.set_register(
        &Variable::mock("RDI", 8 as u64),
        DataDomain::Value(IntervalDomain::new(global_address.clone(), global_address)),
    );

    assert_eq!(
        output,
        get_variable_number_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
            &mem_image,
        )
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
    );
}

#[test]
fn test_parse_format_string_destination_and_return_content() {
    let mem_image = RuntimeMemoryImage::mock();
    let string_address_vector = Bitvector::from_str_radix(16, "3002").unwrap();
    let string_address = DataDomain::Value(IntervalDomain::new(
        string_address_vector.clone(),
        string_address_vector,
    ));

    assert_eq!(
        "Hello World",
        parse_format_string_destination_and_return_content(string_address, &mem_image)
    );
}

#[test]
fn test_parse_format_string_parameters() {
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
        assert_eq!(output, parse_format_string_parameters(case, &properties));
    }
}

#[test]
fn test_map_format_specifier_to_bytesize() {
    let properties = DatatypeProperties::mock();
    assert_eq!(
        ByteSize::new(8),
        map_format_specifier_to_bytesize(&properties, "s".to_string())
    );
    assert_eq!(
        ByteSize::new(8),
        map_format_specifier_to_bytesize(&properties, "f".to_string())
    );
    assert_eq!(
        ByteSize::new(4),
        map_format_specifier_to_bytesize(&properties, "d".to_string())
    );
}

#[test]
#[should_panic]
fn test_map_invalid_format_specifier_to_bytesize() {
    let properties = DatatypeProperties::mock();
    map_format_specifier_to_bytesize(&properties, "w".to_string());
}

#[test]
fn test_calculate_parameter_locations() {
    let project = Project::mock_empty();
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
        calculate_parameter_locations(&project, parameters.clone(), &cconv, format_string_index)
    );

    parameters.push(("s".to_string(), ByteSize::new(4)));
    expected_args.push(Arg::Stack {
        offset: 0,
        size: ByteSize::new(4),
    });

    // Test Case 2: A second string parameter does not fit into the registers anymore and is written into the stack.
    assert_eq!(
        expected_args,
        calculate_parameter_locations(&project, parameters, &cconv, format_string_index)
    );
}

#[test]
fn test_create_string_stack_arg() {
    assert_eq!(
        Arg::Stack {
            size: ByteSize::new(8),
            offset: 8,
        },
        create_string_stack_arg(ByteSize::new(8), 8),
    )
}

#[test]
fn test_create_string_register_arg() {
    assert_eq!(
        Arg::Register(Variable::mock("R9", ByteSize::new(8))),
        create_string_register_arg(ByteSize::new(8), "R9".to_string()),
    );
}

#[test]
fn test_is_integer() {
    assert!(is_integer("d"));
    assert!(is_integer("i"));
    assert!(!is_integer("f"));
}

#[test]
fn test_is_pointer() {
    assert!(is_pointer("s"));
    assert!(is_pointer("S"));
    assert!(is_pointer("n"));
    assert!(is_pointer("p"));
    assert!(!is_pointer("g"));
}

#[test]
fn test_is_string() {
    assert!(is_string("s"));
    assert!(is_string("S"));
    assert!(!is_string("g"));
}

#[test]
fn test_is_float() {
    assert!(is_float("f"));
    assert!(is_float("A"));
    assert!(!is_float("s"));
}
