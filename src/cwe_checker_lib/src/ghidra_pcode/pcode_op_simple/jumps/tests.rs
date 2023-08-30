use crate::{
    expr,
    ghidra_pcode::{
        pcode_op_simple::{tests::*, JmpTarget, PcodeOpSimple, *},
        tests::*,
    },
    intermediate_representation::*,
};

#[test]
fn test_get_jump_target_relative() {
    // backwards jump is lower bounded to 0
    let var = mock_varnode("const".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((0, 0))));

    let var = mock_varnode("const".into(), "0x1".into(), 4);
    let op = mock_pcode_op_branch(7, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((7, 8))));
}

#[test]
fn test_get_jump_target_absolute() {
    // backwards jump is lower bounded to 0
    let var = mock_varnode("ram".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Absolute(0xFFFFFFFF)));
}

#[test]
fn test_extract_target() {
    // Absolute address case
    let var = mock_varnode("ram".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    let expected_target = Tid {
        id: "blk_0xFFFFFFFF".into(),
        address: "0xFFFFFFFF".into(),
    };

    assert_eq!(op.extract_target(&"0x12345678".into()), expected_target);

    // Relative jump to index above 0
    let var = mock_varnode("const".into(), "0x1".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    let expected_target = Tid {
        id: "artificial_blk_0x12345678_1".into(),
        address: "0x12345678".into(),
    };
    assert_eq!(op.extract_target(&"0x12345678".into()), expected_target);

    // Relative jump to index 0
    let var = mock_varnode("const".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(1, var);
    let expected_target = Tid {
        id: "artificial_blk_0x12345678_0".into(),
        address: "0x12345678".into(),
    };
    assert_eq!(op.extract_target(&"0x12345678".into()), expected_target);

    // Relative jump to index below 0. Note: the same targets as above is expected
    let var = mock_varnode("const".into(), "0xFFFFFFFE".into(), 4);
    let op = mock_pcode_op_branch(1, var);

    assert_eq!(op.extract_target(&"0x12345678".into()), expected_target);
}

#[test]
#[should_panic]
fn test_extract_target_circular_jump() {
    let var = mock_varnode("const".into(), "0x0".into(), 4);
    mock_pcode_op_branch(0, var).extract_target(&"0x123456".into());
}

#[test]
fn test_is_pcode_relative_jump() {
    let var = mock_varnode("const".into(), "0x1".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.is_pcode_relative_jump(), true);

    let var = mock_varnode("ram".into(), "0x1".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.is_pcode_relative_jump(), false);

    let var = mock_varnode("const".into(), "0x1".into(), 4);
    let op = mock_pcode_op_add(var, None, None);
    assert_eq!(op.is_pcode_relative_jump(), false)
}

#[test]
fn test_create_branch() {
    let var = mock_varnode("const".into(), "0x002".into(), 4);
    let op = mock_pcode_op_branch(4, var);
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_4".into(),
            address: "0x1111".into(),
        },
        term: Jmp::Branch(Tid {
            id: "artificial_blk_0x1111_6".into(),
            address: "0x1111".into(),
        }),
    };
    assert_eq!(op.create_branch(&"0x1111".into()), expected)
}

#[test]
fn test_create_cbranch() {
    let var_target = mock_varnode("ram".into(), "0x2222".into(), 4);
    let var_condition = mock_varnode("register".into(), "ZF".into(), 1);
    let op = mock_pcode_op_cbranch(1, var_target, var_condition);
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_1".into(),
            address: "0x1111".into(),
        },
        term: Jmp::CBranch {
            target: Tid {
                id: "blk_0x2222".into(),
                address: "0x2222".into(),
            },
            condition: expr!("ZF:1"),
        },
    };
    assert_eq!(op.create_cbranch(&"0x1111".into()), expected)
}

#[test]
fn test_create_branch_indirect() {
    let var_target = mock_varnode("const".into(), "0x002".into(), 4);
    let op = PcodeOpSimple {
        pcode_index: 42,
        pcode_mnemonic: PcodeOperation::JmpType(BRANCHIND),
        input0: var_target,
        input1: None,
        input2: None,
        output: None,
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_42".into(),
            address: "0x1111".into(),
        },
        term: Jmp::BranchInd(expr!("2:4")),
    };
    assert_eq!(op.create_branch_indirect(&"0x1111".into()), expected)
}

#[test]
fn test_create_return() {
    let var_target = mock_varnode("const".into(), "0x7".into(), 4);
    let op = PcodeOpSimple {
        pcode_index: 42,
        pcode_mnemonic: PcodeOperation::JmpType(RETURN),
        input0: var_target,
        input1: None,
        input2: None,
        output: None,
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_42".into(),
            address: "0x1111".into(),
        },
        term: Jmp::Return(expr!("0x7:4")),
    };
    assert_eq!(op.create_return(&"0x1111".into()), expected)
}

#[test]
fn test_create_call() {}

#[test]
fn test_into_ir_jump() {}
