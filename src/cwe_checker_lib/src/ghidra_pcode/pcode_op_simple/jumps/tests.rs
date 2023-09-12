use crate::{
    expr,
    ghidra_pcode::pcode_op_simple::{tests::*, *},
};

#[test]
fn test_get_jump_target_relative() {
    // backwards jump is lower bounded to 0
    let var = VarnodeSimple::mock("const".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((0, 0))));

    let var = VarnodeSimple::mock("const".into(), "0x1".into(), 4);
    let op = mock_pcode_op_branch(7, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((7, 8))));
}

#[test]
fn test_get_jump_target_absolute() {
    // backwards jump is lower bounded to index 0
    let var = VarnodeSimple::mock("ram".into(), "0xFFFFFFFF".into(), 4);
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Absolute(0xFFFFFFFF)));
}

#[test]
fn test_create_branch() {
    let var = VarnodeSimple::mock("const".into(), "0x002".into(), 4);
    let op = mock_pcode_op_branch(4, var);
    let target = Tid {
        id: "blk_0x1111_6".into(),
        address: "0x1111".into(),
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_4".into(),
            address: "0x1111".into(),
        },
        term: Jmp::Branch(target.clone()),
    };
    assert_eq!(op.create_branch(&"0x1111".into(), target), expected)
}

#[test]
fn test_create_cbranch() {
    let var_target = VarnodeSimple::mock("ram".into(), "0x2222".into(), 4);
    let var_condition = VarnodeSimple::mock("register".into(), "ZF".into(), 1);
    let op = mock_pcode_op_cbranch(1, var_target, var_condition);
    let target = Tid {
        id: "blk_0x2222".into(),
        address: "0x2222".into(),
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_1".into(),
            address: "0x1111".into(),
        },
        term: Jmp::CBranch {
            target: target.clone(),
            condition: expr!("ZF:1"),
        },
    };
    assert_eq!(op.create_cbranch(&"0x1111".into(), target), expected)
}

#[test]
fn test_create_branch_indirect() {
    todo!()
}

#[test]
fn test_create_return() {
    todo!()
}

#[test]
fn test_create_call() {
    todo!()
}

#[test]
fn test_create_call_indirect() {
    todo!()
}

#[test]
fn test_create_call_other() {
    todo!()
}

#[test]
fn test_into_ir_jump() {
    todo!()
}
