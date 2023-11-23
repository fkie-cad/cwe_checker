use super::*;
use crate::variable;

/// Mock the abstract location of a global parameter.
fn mock_global(address: u64) -> AbstractLocation {
    AbstractLocation::GlobalAddress {
        address: address,
        size: ByteSize::new(4),
    }
}

impl FunctionSignature {
    /// Create a mock x64 function signature with 2 parameters, one of which is accessed mutably,
    /// one mutably accessed global variable at address 0x2000
    /// and one immutably accessed global variable at address 0x3000.
    pub fn mock_x64() -> FunctionSignature {
        let mut write_access_pattern = AccessPattern::new();
        write_access_pattern.set_unknown_access_flags();
        let parameters = BTreeMap::from_iter([
            (
                AbstractLocation::from_var(&variable!("RDI:8")).unwrap(),
                AccessPattern::new(),
            ),
            (
                AbstractLocation::from_var(&variable!("RSI:8")).unwrap(),
                write_access_pattern,
            ),
        ]);
        FunctionSignature {
            parameters,
            global_parameters: BTreeMap::from([
                (mock_global(0x2000), AccessPattern::new_unknown_access()),
                (
                    mock_global(0x3000),
                    AccessPattern::new().with_dereference_flag(),
                ),
            ]),
        }
    }
}

fn mock_stack_arg(offset: i64, size: u64) -> AbstractLocation {
    AbstractLocation::Pointer(
        variable!("RSP:8"),
        AbstractMemoryLocation::Location {
            offset: offset,
            size: ByteSize::new(size),
        },
    )
}

#[test]
fn test_two_parameter_overlapping_merging() {
    let proj = Project::mock_x64();
    let mut func_sig = FunctionSignature::mock_x64();
    let stack_parm_1 = mock_stack_arg(0x1000, 8);
    let stack_parm_2 = mock_stack_arg(0x1004, 8);

    func_sig
        .parameters
        .insert(stack_parm_1, AccessPattern::new());
    func_sig
        .parameters
        .insert(stack_parm_2, AccessPattern::new());

    assert_eq!(
        func_sig.sanitize(&proj),
        vec!["Unexpected stack parameter size".to_string()],
    );
    let mut expected_function_sig = FunctionSignature::mock_x64();
    let expected_stack_arg = mock_stack_arg(0x1000, 12);

    expected_function_sig
        .parameters
        .insert(expected_stack_arg, AccessPattern::new());
    assert_eq!(func_sig, expected_function_sig);
}

#[test]
fn test_merging_multiple_parameters() {
    let proj = Project::mock_x64();
    let mut func_sig = FunctionSignature::mock_x64();
    let stack_parm_1 = mock_stack_arg(0x8, 8);
    let stack_parm_2 = mock_stack_arg(0x8, 1);
    let stack_parm_3 = mock_stack_arg(0xf, 1);
    let stack_parm_4 = mock_stack_arg(0x10, 8);

    func_sig.parameters.extend([
        (stack_parm_1.clone(), AccessPattern::new()),
        (stack_parm_2, AccessPattern::new()),
        (stack_parm_3, AccessPattern::new()),
        (stack_parm_4.clone(), AccessPattern::new()),
    ]);
    let logs = func_sig.sanitize(&proj);
    assert_eq!(logs, Vec::<String>::new());

    let mut expected_function_sig = FunctionSignature::mock_x64();
    expected_function_sig.parameters.extend([
        (stack_parm_1, AccessPattern::new()),
        (stack_parm_4, AccessPattern::new()),
    ]);
    assert_eq!(func_sig, expected_function_sig);
}
#[test]
fn test_log_messages() {
    let proj = Project::mock_x64();
    let mut func_sig = FunctionSignature::mock_x64();
    let stack_parm_1 = mock_stack_arg(0x1001, 8);
    let stack_parm_2 = mock_stack_arg(0x1007, 4);

    func_sig.parameters.extend([
        (stack_parm_1.clone(), AccessPattern::new()),
        (stack_parm_2, AccessPattern::new()),
    ]);

    let logs = func_sig.sanitize(&proj);
    assert_eq!(
        vec![
            "Unexpected stack parameter size".to_string(),
            "Unexpected stack parameter alignment".to_string()
        ],
        logs
    );
}
