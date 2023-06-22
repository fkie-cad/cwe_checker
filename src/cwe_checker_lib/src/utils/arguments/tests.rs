use std::collections::BTreeSet;

use crate::{abstract_domain::IntervalDomain, expr, intermediate_representation::*, variable};

use super::*;

fn mock_pi_state() -> PointerInferenceState {
    PointerInferenceState::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new())
}

#[test]
/// Tests extraction of format string parameters '/dev/sd%c%d' and 'cat %s'.
fn test_get_variable_parameters() {
    let mut pi_state = mock_pi_state();
    let sprintf_symbol = ExternSymbol::mock_sprintf_x64();
    let mut format_string_index_map: HashMap<String, usize> = HashMap::new();
    format_string_index_map.insert("sprintf".to_string(), 1);
    let global_address = Bitvector::from_str_radix(16, "5000").unwrap();
    pi_state.set_register(
        &variable!("RSI:8"),
        IntervalDomain::new(global_address.clone(), global_address).into(),
    );
    let project = Project::mock_x64();

    let mut output: Vec<Arg> = Vec::new();
    output.push(Arg::from_var(variable!("RDX:8"), Some(Datatype::Char)));
    output.push(Arg::from_var(variable!("RCX:8"), Some(Datatype::Integer)));

    assert_eq!(
        output,
        get_variable_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
        )
        .unwrap()
    );

    output = vec![Arg::from_var(variable!("RDX:8"), Some(Datatype::Pointer))];

    let global_address = Bitvector::from_str_radix(16, "500c").unwrap();
    pi_state.set_register(
        &variable!("RSI:8"),
        IntervalDomain::new(global_address.clone(), global_address).into(),
    );

    assert_eq!(
        output,
        get_variable_parameters(
            &project,
            &pi_state,
            &sprintf_symbol,
            &format_string_index_map,
        )
        .unwrap()
    );
}

#[test]
fn test_get_input_format_string() {
    let mem_image = RuntimeMemoryImage::mock();
    let mut pi_state = mock_pi_state();
    let sprintf_symbol = ExternSymbol::mock_sprintf_x64();

    let global_address = Bitvector::from_str_radix(16, "3002").unwrap();
    pi_state.set_register(
        &variable!("RSI:8"),
        IntervalDomain::new(global_address.clone(), global_address).into(),
    );

    assert_eq!(
        "Hello World",
        get_input_format_string(&pi_state, &sprintf_symbol, 1, &mem_image).unwrap()
    );
}

#[test]
fn test_parse_format_string_destination_and_return_content() {
    let mem_image = RuntimeMemoryImage::mock();
    let string_address = Bitvector::from_str_radix(16, "3002").unwrap();

    assert_eq!(
        "Hello World",
        parse_format_string_destination_and_return_content(string_address, &mem_image).unwrap()
    );
}

/// Test the regular expression used for format string parameter parsing on specific cases.
#[test]
fn test_format_string_regex() {
    let regex = Regex::new(r#"%[+\-#0]{0,1}\d*[\.]?\d*([cCdiouxXeEfFgGaAnpsS]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
        .expect("No valid regex!");

    let format_string = "one %s, two %.2lf%%, three %.2lf%%";
    let results: Vec<_> = regex
        .captures_iter(format_string)
        .map(|cap| cap[1].to_string())
        .collect();
    assert_eq!(&results[..], vec!["s", "lf", "lf"]);

    let format_string = "test %+2.300f,%-2.300f%#2.300f%02.300f";
    let results: Vec<_> = regex
        .captures_iter(format_string)
        .map(|cap| cap[1].to_string())
        .collect();
    assert_eq!(&results[..], vec!["f", "f", "f", "f"]);

    let format_string = r#"%cCd %ss %256s /dev/bus/usb/%03d/%s"#;
    let results: Vec<_> = regex
        .captures_iter(format_string)
        .map(|cap| cap[1].to_string())
        .collect();
    assert_eq!(&results[..], vec!["c", "s", "s", "d", "s"]);
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
    let properties = DatatypeProperties::mock_x64();
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
/// Tests tracking of parameters according to format string
fn test_calculate_parameter_locations() {
    let project = Project::mock_x64();
    let extern_symbol = ExternSymbol::mock_sprintf_x64();
    let mut parameters: Vec<(Datatype, ByteSize)> = Vec::new();
    parameters.push(("d".to_string().into(), ByteSize::new(8)));
    parameters.push(("f".to_string().into(), ByteSize::new(16)));
    parameters.push(("s".to_string().into(), ByteSize::new(8)));

    let mut expected_args = vec![
        Arg::Register {
            expr: expr!("RDX:8"),
            data_type: Some(Datatype::Integer),
        },
        Arg::Register {
            expr: Expression::subpiece(expr!("ZMM0:64"), ByteSize::new(0), ByteSize::new(8)),
            data_type: Some(Datatype::Double),
        },
        Arg::Register {
            expr: expr!("RCX:8"),
            data_type: Some(Datatype::Pointer),
        },
    ];

    // Test Case 1: The string parameter is still written in the RCX register since 'f' is contained in the float register.
    assert_eq!(
        expected_args,
        calculate_parameter_locations(parameters.clone(), &extern_symbol, &project,)
    );

    parameters.push(("s".to_string().into(), ByteSize::new(8)));
    parameters.push(("s".to_string().into(), ByteSize::new(8)));
    parameters.push(("s".to_string().into(), ByteSize::new(8)));

    expected_args.push(Arg::Register {
        expr: expr!("R8:8"),
        data_type: Some(Datatype::Pointer),
    });
    expected_args.push(Arg::Register {
        expr: expr!("R9:8"),
        data_type: Some(Datatype::Pointer),
    });
    expected_args.push(Arg::Stack {
        address: expr!("RSP:8 + 8:8"),
        size: ByteSize::new(8),
        data_type: Some(Datatype::Pointer),
    });

    // Test Case 2: Three further string parameter does not fit into the registers anymore and one is written into the stack.
    assert_eq!(
        expected_args,
        calculate_parameter_locations(parameters, &extern_symbol, &project)
    );
}

#[test]
fn test_create_stack_arg() {
    assert_eq!(
        Arg::Stack {
            address: expr!("RSP:8 + 8:8"),
            size: ByteSize::new(8),
            data_type: Some(Datatype::Pointer),
        },
        create_stack_arg(ByteSize::new(8), 8, Datatype::Pointer, &variable!("RSP:8")),
    )
}
