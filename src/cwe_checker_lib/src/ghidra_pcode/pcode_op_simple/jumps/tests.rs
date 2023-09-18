use crate::{expr, ghidra_pcode::pcode_op_simple::*};

#[test]
fn test_get_direct_jump_target() {
    let mut instr = InstructionSimple::mock(
        "0x1000",
        [
            "BRANCH const_0xFFFFFFFD_4",
            "CBRANCH const_0x02_4 register_ZF_1",
            "CALL ram_0x1234_4",
            "BRANCH const_0x10_4",
        ],
    );
    instr.fall_through = Some("0x1001".into());
    // P-Code-relative backward jump is lower bounded to 0
    assert_eq!(
        instr.pcode_ops[0].get_direct_jump_target(&instr),
        Tid::mock("blk_0x1000")
    );
    // normal P-Code relative jump
    assert_eq!(
        instr.pcode_ops[1].get_direct_jump_target(&instr),
        Tid::mock("blk_0x1000_3")
    );
    // jump to ram address
    assert_eq!(
        instr.pcode_ops[2].get_direct_jump_target(&instr),
        Tid::mock("blk_0x1234")
    );
    // relative P-Code-jumps above max index jump to fall-through address
    assert_eq!(
        instr.pcode_ops[3].get_direct_jump_target(&instr),
        Tid::mock("blk_0x1001")
    );
}

#[test]
fn test_get_fall_through_target() {
    let mut instr = InstructionSimple::mock(
        "0x1000",
        [
            "CBRANCH ram_0x1234_4 register_ZF_1",
            "CALLOTHER ram_0x1234_4",
            "CALL ram_0x1234_4",
        ],
    );
    instr.fall_through = Some("0x1010".into());
    assert_eq!(
        instr.pcode_ops[0].get_fall_through_target(&instr).unwrap(),
        Tid::mock("blk_0x1000_1")
    );
    assert_eq!(
        instr.pcode_ops[1].get_fall_through_target(&instr).unwrap(),
        Tid::mock("blk_0x1000_2")
    );
    assert_eq!(
        instr.pcode_ops[2].get_fall_through_target(&instr).unwrap(),
        Tid::mock("blk_0x1010")
    );
    // Test the case of artificial Call-Return pairs
    let mut instr =
        InstructionSimple::mock("0x1000", ["CALLIND ram_0x1234_4", "RETURN register_EAX_4"]);
    instr.fall_through = Some("0x1010".into());
    assert_eq!(
        instr.pcode_ops[0].get_fall_through_target(&instr).unwrap(),
        Tid::mock("blk_0x1000_1")
    );
}

#[test]
fn test_collect_jump_targets() {
    let mut instr = InstructionSimple::mock(
        "0x1000",
        [
            "CBRANCH ram_0x2000_4 register_ZF_1",
            "CALLIND register_EAX_4",
        ],
    );
    instr.potential_targets = Some(vec!["0x3001".into(), "0x3002".into(), "0x3003".into()]);
    assert_eq!(
        instr.pcode_ops[0].collect_jmp_targets(&instr),
        vec![Tid::mock("blk_0x2000")]
    );
    // Note that despite CALLIND being a call, the collected TIDs are block TIDs.
    assert_eq!(
        instr.pcode_ops[1].collect_jmp_targets(&instr),
        vec![
            Tid::mock("blk_0x3001"),
            Tid::mock("blk_0x3002"),
            Tid::mock("blk_0x3003")
        ]
    );
}

#[test]
fn test_create_branch() {
    let instr = InstructionSimple::mock("0x1000", ["BRANCH ram_0x1234_4"]);
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::Branch(Tid::mock("blk_0x1234"))
        }
    );
    let mut instr = InstructionSimple::mock("0x1000", ["BRANCH const_0x2_4"]);
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::Branch(Tid::mock("blk_0x1001"))
        }
    );
}

#[test]
fn test_create_cbranch() {
    let instr = InstructionSimple::mock(
        "0x1000",
        [
            "CBRANCH const_0x2_4 register_ZF_1",
            "register_RAX_8 INT_ADD register_RAX_8 register_RAX_8",
            "register_RAX_8 INT_ADD register_RAX_8 register_RAX_8",
        ],
    );
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::CBranch {
                target: Tid::mock("blk_0x1000_2"),
                condition: expr!("ZF:1")
            }
        }
    );
}

#[test]
fn test_create_branch_indirect() {
    let instr = InstructionSimple::mock("0x1000", ["BRANCHIND register_pc_4"]);
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::BranchInd(expr!("pc:4"))
        }
    );
}

#[test]
fn test_create_call() {
    let mut instr = InstructionSimple::mock("0x1000", ["CALL ram_0x1234_4"]);
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::Call {
                target: Tid::mock("FUN_0x1234"),
                return_: Some(Tid::mock("blk_0x1001"))
            }
        }
    );
}

#[test]
fn test_create_call_indirect() {
    let mut instr = InstructionSimple::mock("0x1000", ["CALLIND register_EAX_4"]);
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::CallInd {
                target: expr!("EAX:4"),
                return_: Some(Tid::mock("blk_0x1001"))
            }
        }
    );
}

#[test]
fn test_create_return() {
    let mut instr = InstructionSimple::mock("0x1000", ["RETURN register_EAX_4"]);
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::Return(expr!("EAX:4"))
        }
    );
}

#[test]
fn test_create_call_other() {
    let mut instr = InstructionSimple::mock("0x1000", ["CALLOTHER register_EAX_4"]);
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::CallOther {
                description: "mock".into(),
                return_: Some(Tid::mock("blk_0x1001"))
            }
        }
    );
    // CallOther is the only "Call" instruction where the fall-through is the next P-Code instruction
    // and not necessarily the next assembly instruction
    let mut instr = InstructionSimple::mock(
        "0x1000",
        [
            "CALLOTHER register_EAX_4",
            "register_RAX_8 INT_ADD register_RAX_8 register_RAX_8",
        ],
    );
    instr.fall_through = Some("0x1001".into());
    assert_eq!(
        instr.pcode_ops[0].into_ir_jump(&instr),
        Term {
            tid: Tid::mock("instr_0x1000_0"),
            term: Jmp::CallOther {
                description: "mock".into(),
                return_: Some(Tid::mock("blk_0x1000_1"))
            }
        }
    );
}
