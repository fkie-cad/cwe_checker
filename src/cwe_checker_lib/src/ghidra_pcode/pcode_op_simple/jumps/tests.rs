use crate::{expr, ghidra_pcode::pcode_op_simple::*};

#[test]
fn test_get_jump_target_relative() {
    let op = PcodeOpSimple::mock("BRANCH const_0x1_4").with_index(4);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((4, 5))));
    let op = PcodeOpSimple::mock("BRANCH const_0xFFFFFFFD_4").with_index(4);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((4, 1))));
    // backwards jump is lower bounded to 0
    let op = PcodeOpSimple::mock("BRANCH const_0xFFFFFFFD_4").with_index(1);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((1, 0))));
}

#[test]
fn test_get_jump_target_absolute() {
    let op = PcodeOpSimple::mock("BRANCH ram_0xABCD_4");
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Absolute(0xABCD)));
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
}
