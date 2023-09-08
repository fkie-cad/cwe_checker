use super::{
    pcode_op_simple::tests::{mock_pcode_op_add, mock_pcode_op_branch},
    *,
};
use crate::{
    bitvec, def, expr, ghidra_pcode::pcode_op_simple::tests::mock_pcode_op_cbranch, variable,
};
use pcode_operations::PcodeOperation::JmpType;

pub fn mock_varnode(addressspace: &str, id: &str, size: u64) -> VarnodeSimple {
    VarnodeSimple {
        address_space: addressspace.to_string(),
        id: id.to_string(),
        size,
    }
}

/// Returns `InstructionSimple`, with mnemonic `mock`, size `1`, `potential_targets` and `fall_through` set to `None`-
fn mock_instruction(address: String, pcode_ops: Vec<PcodeOpSimple>) -> InstructionSimple {
    InstructionSimple {
        mnemonic: "mock".into(),
        address: address,
        size: 1,
        pcode_ops: pcode_ops,
        potential_targets: None,
        fall_through: None,
    }
}
#[test]
fn test_varnode_into_const() {
    if let Expression::Const(c) = mock_varnode("const", "0x0", 8).into_ir_expr().unwrap() {
        assert_eq!(c, bitvec!("0x0:8"));
    } else {
        panic!("not an IR constant")
    }
    if let Expression::Const(c) = mock_varnode("const", "0x42", 4).into_ir_expr().unwrap() {
        assert_eq!(c, bitvec!("0x42:4"));
    } else {
        panic!("not an IR constant")
    }
    if let Expression::Const(c) = mock_varnode("const", "0xFFFFFFFF", 4)
        .into_ir_expr()
        .unwrap()
    {
        assert_eq!(c, bitvec!("0x-1:4"));
    } else {
        panic!("not an IR constant")
    }
}

#[test]
fn test_varnode_into_var() {
    if let Expression::Var(v) = mock_varnode("register", "RSP", 8).into_ir_expr().unwrap() {
        assert_eq!(v, variable!("RSP:8"));
    } else {
        panic!("not an IR variable")
    }
}

#[test]
fn test_varnode_into_temp_var() {
    if let Expression::Var(v) = mock_varnode("unique", "virtual", 8).into_ir_expr().unwrap() {
        assert_eq!(
            v,
            Variable {
                name: "$U_virtual".into(),
                size: 8.into(),
                is_temp: true
            }
        );
    } else {
        panic!("not an IR virtual variable")
    }
}

#[test]
fn test_varnode_alternative_addressspace() {
    assert!(mock_varnode("something", "id", 8).into_ir_expr().is_err());
}

#[test]
fn test_varnode_into_ram_address() {
    assert_eq!(
        mock_varnode("ram", "0xFF11", 8).get_ram_address(),
        Some(bitvec!("0xFF11:8"))
    );
}

#[test]
fn test_alternative_varnode_into_ram_address() {
    assert_eq!(
        mock_varnode("something", "0xFF11", 8).get_ram_address(),
        None
    );
}

#[test]
fn test_into_explicit_load() {
    todo!()
}

#[test]
fn test_instruction_get_u64_address() {
    let mut instr = InstructionSimple {
        mnemonic: "nop".into(),
        address: "0x00123ABFF".into(),
        size: 2,
        pcode_ops: vec![],
        potential_targets: None,
        fall_through: None,
    };
    assert_eq!(instr.get_u64_address(), 0x123ABFF);
    instr.address = "0x123ABFF".into();
    assert_eq!(instr.get_u64_address(), 0x123ABFF);
}

#[test]
#[should_panic]
fn test_instruction_get_u64_address_not_hex() {
    mock_instruction("0xABG".into(), vec![]).get_u64_address();
}

#[test]
fn test_get_best_guess_fallthrough_addr() {
    todo!()
}

#[test]
fn test_instruction_collect_jmp_targets() {
    todo!()
}

#[test]
fn test_block_collect_jmp_targets() {
    let target_a = mock_varnode("ram".into(), "0x1234".into(), 8);
    let target_b = mock_varnode("ram".into(), "0xFFFFFFFF".into(), 8);
    let target_relative_next_op = mock_varnode("const".into(), "0x1".into(), 8);

    let instr = mock_instruction(
        "0x01000".into(),
        vec![
            mock_pcode_op_branch(0, target_a),
            mock_pcode_op_branch(1, target_b).with_mnemonic(JmpType(CALL)),
            mock_pcode_op_branch(2, target_relative_next_op.clone())
                .with_mnemonic(JmpType(CBRANCH)),
            mock_pcode_op_branch(3, target_relative_next_op).with_mnemonic(JmpType(RETURN)),
        ],
    );
    let next_instr = mock_instruction("0x1007".into(), vec![]);
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
    let mut blk = Blk {
        defs: vec![],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };
    let mut tid = Tid::new("blk_tid");
    let varnode = mock_varnode("register".into(), "EAX".into(), 4);
    let op_add = mock_pcode_op_add(varnode.clone(), Some(varnode.clone()), Some(varnode));
    let op_cbranch_forward = mock_pcode_op_cbranch(
        0,
        mock_varnode("const", "0x2", 4),
        mock_varnode("register".into(), "ZF".into(), 4),
    );
    let pcode_ops = vec![
        op_cbranch_forward,
        op_add.clone().with_index(1),
        op_add.with_index(2),
    ];
    let instr = mock_instruction("0x0100".into(), pcode_ops);
    let blk = BlockSimple {
        address: "0x0100".into(),
        instructions: vec![instr],
    };
    let jmp_targets = blk.collect_jmp_targets();
    dbg!(&jmp_targets);

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
            id: "instr_0x0100_0_implicit_branch".into(),
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
            id: "instr_0x0100_1_implicit_jmp".into(),
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
    assert_eq!(result.get(2).unwrap().term, expected_returned_blk);
    let expected_tid_returned_block = Tid {
        id: "blk_0x0100_2".into(),
        address: "0x0100".into(),
    };
    assert_eq!(tid, expected_tid_returned_block);
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
                    │   │ADD2    │   ┌───────┐
                    └───┤CBRANCH │   │       │
                        │BRANCH  ├─► │       │
                        └────────┘   └───────┘
     */
    let mut blk = Blk {
        defs: vec![],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };
    let mut tid = Tid::new("blk_tid");
    let varnode = mock_varnode("register".into(), "EAX".into(), 4);
    let op_add = mock_pcode_op_add(varnode.clone(), Some(varnode.clone()), Some(varnode));
    let op_cbranch_backward = mock_pcode_op_cbranch(
        2,
        mock_varnode("const", "0xFFFFFFFF", 4),
        mock_varnode("register".into(), "ZF".into(), 4),
    );
    let pcode_ops = vec![
        op_add.clone().with_index(0),
        op_add.with_index(1),
        op_cbranch_backward,
    ];
    let instr = mock_instruction("0x0200".into(), pcode_ops);
    let blk = BlockSimple {
        address: "0x0200".into(),
        instructions: vec![instr],
    };
    let jmp_targets = blk.collect_jmp_targets();
    let result = blk.into_ir_blk(&jmp_targets);

    // We expect three finalized blocks
    assert_eq!(result.len(), 3);

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
            id: "implicit_jmp_0x0200_0".into(),
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
    assert_eq!(result.get(0).unwrap().term, first_expected_blk);
    assert_eq!(result.get(0).unwrap().tid, Tid::new("blk_tid"));

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
            id: "implicit_jmp_0x0200_2".into(),
            address: "0x0200".into(),
        },
        term: Jmp::Branch(Tid {
            id: "blk_0x0207".into(),
            address: "0x0207".into(),
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

    // Check third block
    assert_eq!(
        result.get(2).unwrap().term,
        Blk {
            defs: vec![],
            jmps: vec![],
            indirect_jmp_targets: vec![]
        }
    );
    let expected_tid_returned_block = Tid {
        id: "blk_0x0207".into(),
        address: "0x0207".into(),
    };
    assert_eq!(tid, expected_tid_returned_block);
}
