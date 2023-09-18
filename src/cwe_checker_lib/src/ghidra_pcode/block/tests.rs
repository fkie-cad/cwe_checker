use super::*;
use crate::ghidra_pcode::pcode_op_simple::tests::*;
use crate::ghidra_pcode::PcodeOperation::JmpType;
use crate::ghidra_pcode::VarnodeSimple;
use crate::{def, expr};

#[test]
fn test_block_collect_jmp_targets() {
    let target_a = VarnodeSimple::mock("ram_0x1234_8");
    let target_b = VarnodeSimple::mock("ram_0xFFFFFFFF_8");
    let target_relative_next_op = VarnodeSimple::mock("const_0x1_8");

    let instr = InstructionSimple::mock(
        "0x01000".into(),
        [
            "BRANCH ram_0x1234_8",
            "CALL ram_0xFFFFFFFF_8",
            "CBRANCH const_0x1_8 register_ZF_1",
            "RETURN const_0x1_8",
        ],
    );
    let next_instr = InstructionSimple::mock("0x1007".into(), Vec::<&str>::new());
    let blk = BlockSimple {
        address: "0x01000".into(),
        instructions: vec![instr, next_instr],
    };

    let expected_tid_a = Tid {
        id: "blk_0x1234".into(),
        address: "0x1234".into(),
    };
    let expected_tid_b = Tid {
        id: "blk_0xFFFFFFFF".into(),
        address: "0xFFFFFFFF".into(),
    };
    let expected_tid_relative_next_op = Tid {
        id: "blk_0x01000_3".into(),
        address: "0x01000".into(),
    };
    let expected_tid_next_instr = Tid {
        id: "blk_0x1007".into(),
        address: "0x1007".into(),
    };
    assert_eq!(
        blk.collect_jmp_targets(),
        HashSet::from([
            expected_tid_a,
            expected_tid_b,
            expected_tid_next_instr,
            expected_tid_relative_next_op
        ])
    )
}

#[test]
fn test_pcode_relative_jump_forward_jump() {
    /*
       Instruction:       ┌───────┐    Blocks:
                          │CBRANCH├─────────┐
           CBRANCH─┐      │BRANCH │         ▼
           ADD1    │ ==>  └───┬───┘     ┌────────┐
           ADD2 ◄──┘          │         │ ADD2   │
                              ▼         │        │
                           ┌───────┐    └────────┘
                           │ADD1   │         ▲
                           │BRANCH ├─────────┘
                           └───────┘
    */
    let tid = Tid::new("blk_tid");
    let varnode = VarnodeSimple::mock("register_EAX_4");
    let op_add = mock_pcode_op_add(varnode.clone(), Some(varnode.clone()), Some(varnode));
    let op_cbranch_forward = mock_pcode_op_cbranch(
        0,
        VarnodeSimple::mock("const_0x2_4"),
        VarnodeSimple::mock("register_ZF_1"),
    );
    let pcode_ops = vec![
        "CBRANCH const_0x2_4 register_ZF_1",
        "register_EAX_4 INT_ADD register_EAX_4 register_EAX_4",
        "register_EAX_4 INT_ADD register_EAX_4 register_EAX_4",
    ];
    let instr = InstructionSimple::mock("0x0100".into(), pcode_ops);
    let blk = BlockSimple {
        address: "0x0100".into(),
        instructions: vec![instr],
    };
    let jmp_targets = blk.collect_jmp_targets();

    let result = blk.into_ir_blk(&jmp_targets);

    // We expect three finalized blocks
    assert_eq!(result.len(), 3);

    // Check first finalized block
    let first_expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0100_0".into(),
            address: "0x0100".into(),
        },
        term: Jmp::CBranch {
            target: Tid {
                id: "blk_0x0100_2".into(),
                address: "0x0100".into(),
            },
            condition: expr!("ZF:4"),
        },
    };
    let second_expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0100_0_implicit_jump".into(),
            address: "0x0100".into(),
        },
        term: Jmp::Branch(Tid {
            id: "blk_0x0100_1".into(),
            address: "0x0100".into(),
        }),
    };
    let first_expected_blk = Blk {
        defs: vec![],
        jmps: vec![first_expected_jmp, second_expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(result.get(0).unwrap().term, first_expected_blk);

    let expected_tid = Tid {
        id: "blk_0x0100".into(),
        address: "0x0100".into(),
    };
    assert_eq!(result.get(0).unwrap().tid, expected_tid);

    // Check second finalized block
    let expected_def = Term {
        tid: Tid {
            id: "instr_0x0100_1".into(),
            address: "0x0100".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0100_1_implicit_jump".into(),
            address: "0x0100".into(),
        },
        term: Jmp::Branch(Tid {
            id: "blk_0x0100_2".into(),
            address: "0x0100".into(),
        }),
    };
    let second_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(result.get(1).unwrap().term, second_expected_blk);
    let expected_tid_second_block = Tid {
        id: "blk_0x0100_1".into(),
        address: "0x0100".into(),
    };
    assert_eq!(result.get(1).unwrap().tid, expected_tid_second_block);

    // Check third block
    let expected_def_of_returned_blk = Term {
        tid: Tid {
            id: "instr_0x0100_2".into(),
            address: "0x0100".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let expected_returned_blk = Blk {
        defs: vec![expected_def_of_returned_blk],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };
    // TODO: The test fails, because the best-effort logic also generates a jump at the end of the block
    // to an assumed next block.
    // We have to check with the Ghidra output of real binaries to test whether the best-effort-logic is correct or not.
    assert_eq!(result.get(2).unwrap().term, expected_returned_blk);
    let expected_tid_returned_block = Tid {
        id: "blk_0x0100_2".into(),
        address: "0x0100".into(),
    };
    assert_eq!(tid, expected_tid_returned_block);
}

#[test]
fn test_block_generation_with_empty_instruction_array() {
    // TODO: This case should probably panic,
    // but the most important thing is that it does not run into an infinite loop.
    todo!()
}

#[test]
fn test_process_pcode_relative_jump_backward_jump() {
    /*
    Instruction:          Blocks:
                     ┌──────┐
    ADD1             │ADD1  │
    ADD2 ◄──┐   ==>  │BRANCH├─┐
    CBRANCH ┘        └──────┘ │
                              │
                    ┌────┐    │
                    │    ▼    ▼
                    │   ┌────────┐
                    │   │ADD2    │
                    └───┤CBRANCH │
                        │BRANCH  |
                        └────────┘
     */
    let varnode = VarnodeSimple::mock("register_EAX_4");
    let op_add = mock_pcode_op_add(varnode.clone(), Some(varnode.clone()), Some(varnode));
    let op_cbranch_backward = mock_pcode_op_cbranch(
        2,
        VarnodeSimple::mock("const_0xFFFFFFFF_4"),
        VarnodeSimple::mock("register_ZF_1"),
    );
    let pcode_ops = vec![
        "register_EAX_4 INT_ADD register_EAX_4 register_EAX_4",
        "register_EAX_4 INT_ADD register_EAX_4 register_EAX_4",
        "CBRANCH const_0xFFFFFFFF_4 register_ZF_1",
    ];
    let instr = InstructionSimple::mock("0x0200".into(), pcode_ops);
    let blk = BlockSimple {
        address: "0x0200".into(),
        instructions: vec![instr],
    };
    let jmp_targets = blk.collect_jmp_targets();
    let result = blk.into_ir_blk(&jmp_targets);

    // We expect three finalized blocks
    assert_eq!(result.len(), 2);

    // Check first finalized block
    let expected_def = Term {
        tid: Tid {
            id: "instr_0x0200_0".into(),
            address: "0x0200".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0200_0_implicit_jump".into(),
            address: "0x0200".into(),
        },
        term: Jmp::Branch(Tid {
            id: "blk_0x0200_1".into(),
            address: "0x0200".into(),
        }),
    };
    let first_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(result[0].term, first_expected_blk);
    assert_eq!(
        result[0].tid,
        Tid {
            id: "blk_0x0200".to_string(),
            address: "0x0200".to_string()
        }
    );

    // Check second finalized block
    let second_finalized_blk = result.get(1).unwrap();
    let expected_def = Term {
        tid: Tid {
            id: "instr_0x0200_1".into(),
            address: "0x0200".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let first_expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0200_2".into(),
            address: "0x0200".into(),
        },
        term: Jmp::CBranch {
            target: Tid {
                id: "blk_0x0200_1".into(),
                address: "0x0200".into(),
            },
            condition: expr!("ZF:4"),
        },
    };
    let second_expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0200_2_implicit_jump".into(),
            address: "0x0200".into(),
        },
        term: Jmp::Branch(Tid {
            id: "blk_0x0201".into(),
            address: "0x0201".into(),
        }),
    };
    let second_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![first_expected_jmp, second_expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(second_finalized_blk.term, second_expected_blk);
    let expected_tid_second_block = Tid {
        id: "blk_0x0200_1".into(),
        address: "0x0200".into(),
    };
    assert_eq!(second_finalized_blk.tid, expected_tid_second_block);
}
