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

fn mock_instruction(address: String, pcode_ops: Vec<PcodeOpSimple>) -> InstructionSimple {
    InstructionSimple {
        mnemonic: "mock".into(),
        address: address,
        pcode_ops: pcode_ops,
        potential_targets: None,
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
fn test_instruction_get_u64_address() {
    let mut instr = InstructionSimple {
        mnemonic: "nop".into(),
        address: "0x00123ABFF".into(),
        pcode_ops: vec![],
        potential_targets: None,
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
fn test_contains_relative_jump_to_next_instruction_true() {
    let op = mock_varnode("const".into(), "0x1".into(), 8);
    let instr = mock_instruction("0x01000".into(), vec![mock_pcode_op_branch(0, op)]);
    assert!(instr.contains_relative_jump_to_next_instruction())
}

#[test]
fn test_contains_relative_jump_to_next_instruction_false() {
    // jump within pcode op sequence
    let op_within_sequence = mock_varnode("const".into(), "0x0".into(), 8);
    // jump one pcode op back
    let op_backwards_within_sequence = mock_varnode("const".into(), "0xFFFFFFFF".into(), 4);
    let instr = mock_instruction(
        "0x01000".into(),
        vec![
            mock_pcode_op_branch(0, op_within_sequence),
            mock_pcode_op_branch(1, op_backwards_within_sequence),
        ],
    );
    assert_eq!(instr.contains_relative_jump_to_next_instruction(), false)
}

#[test]
fn test_collect_jmp_targets() {
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
    assert_eq!(
        blk.collect_jmp_targets(),
        [0x1234, 0xFFFFFFFF, 0x1007].into()
    )
}

#[test]
fn test_blk_into_ir() {}

#[test]
fn test_finalize_blk_and_setup_new_blk() {
    let mut blk = Blk {
        defs: vec![],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };
    let mut tid = Tid::new("tid_id");
    let (finalized, new_blk, new_tid) =
        finalize_blk_and_setup_new_blk(&mut tid, &mut blk, "0x123_4_5".into());

    assert_eq!(
        new_tid,
        Tid {
            id: "artificial_blk_0x123_4_5".into(),
            address: "0x123".into()
        }
    );
    assert_eq!(blk, new_blk); // should be an "empty" block anyway
    assert_eq!(Term { tid, term: blk }, finalized);
}

#[test]
fn test_finalize_blk_with_branch_and_setup_new_blk() {
    let mut blk = Blk {
        defs: vec![],
        jmps: vec![],
        indirect_jmp_targets: vec![],
    };
    let mut tid = Tid::new("blk_tid");
    let (finalized, new_blk, new_tid) = finalize_blk_with_branch_and_setup_new_blk(
        &mut tid,
        &mut blk,
        "0xACB_D_E".into(),
        "0x123_4_5".into(),
    );

    assert_eq!(
        new_tid,
        Tid {
            id: "artificial_blk_0x123_4_5".into(),
            address: "0x123".into()
        }
    );
    assert_eq!(blk, new_blk); // should be an "empty" block anyway

    // prepare expected block with branch
    let branch = Term {
        tid: Tid {
            id: format!("artificial_jmp_0xACB_D_E"),
            address: "0xACB".into(),
        },
        term: Jmp::Branch(new_tid.clone()),
    };
    blk.jmps.push(branch);
    assert_eq!(Term { tid, term: blk }, finalized);
}

#[test]
fn test_process_pcode_relative_jump_forward_jump() {
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
    let result = process_pcode_relative_jump(&mut tid, &mut blk, instr, Some("0x107".into()));

    //We expect two finalized blocks
    assert_eq!(result.len(), 2);

    let first_finalized_blk = result.get(0).unwrap();
    let first_expected_jmp = Term {
        tid: Tid {
            id: "instr_0x0100_0".into(),
            address: "0x0100".into(),
        },
        term: Jmp::CBranch {
            target: Tid {
                id: "artificial_blk_0x0100_2".into(),
                address: "0x0100".into(),
            },
            condition: expr!("ZF:4"),
        },
    };
    let second_expected_jmp = Term {
        tid: Tid {
            id: "artificial_jmp_0x0100_0".into(),
            address: "0x0100".into(),
        },
        term: Jmp::Branch(Tid {
            id: "artificial_blk_0x0100_1".into(),
            address: "0x0100".into(),
        }),
    };
    let first_expected_blk = Blk {
        defs: vec![],
        jmps: vec![first_expected_jmp, second_expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(first_finalized_blk.term, first_expected_blk);

    let second_finalized_blk = result.get(1).unwrap();
    let expected_def = Term {
        tid: Tid {
            id: "instr_0x0100_1".into(),
            address: "0x0100".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let expected_jmp = Term {
        tid: Tid {
            id: "artificial_jmp_0x0100_1".into(),
            address: "0x0100".into(),
        },
        term: Jmp::Branch(Tid {
            id: "artificial_blk_0x0100_2".into(),
            address: "0x0100".into(),
        }),
    };
    let second_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(second_finalized_blk.term, second_expected_blk);

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
    assert_eq!(blk, expected_returned_blk);

    // Checking TIDs of blocks. Skipping first block, since TID is provided.
    let expected_tid_second_block = Tid {
        id: "artificial_blk_0x0100_1".into(),
        address: "0x0100".into(),
    };
    assert_eq!(second_finalized_blk.tid, expected_tid_second_block);

    let expected_tid_returned_block = Tid {
        id: "artificial_blk_0x0100_2".into(),
        address: "0x0100".into(),
    };
    assert_eq!(tid, expected_tid_returned_block);
}

#[test]
fn test_process_pcode_relative_jump_backward_jump() {
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
    let result = process_pcode_relative_jump(&mut tid, &mut blk, instr, Some("0x0207".into()));

    // We expect two finalized blocks
    assert_eq!(result.len(), 2);

    let first_finalized_blk = result.get(0).unwrap();
    let expected_def = Term {
        tid: Tid {
            id: "instr_0x0200_0".into(),
            address: "0x0200".into(),
        },
        term: def!["EAX:4 = EAX:4 + EAX:4"].term,
    };
    let expected_jmp = Term {
        tid: Tid {
            id: "artificial_jmp_0x0200_0".into(),
            address: "0x0200".into(),
        },
        term: Jmp::Branch(Tid {
            id: "artificial_blk_0x0200_1".into(),
            address: "0x0200".into(),
        }),
    };
    let first_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(first_finalized_blk.term, first_expected_blk);

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
                id: "artificial_blk_0x0200_1".into(),
                address: "0x0200".into(),
            },
            condition: expr!("ZF:4"),
        },
    };
    let second_expected_jmp = Term {
        tid: Tid {
            id: "artificial_jmp_0x0200_2".into(),
            address: "0x0200".into(),
        },
        term: Jmp::Branch(Tid {
            id: "artificial_blk_0x0207".into(),
            address: "0x0207".into(),
        }),
    };
    let second_expected_blk = Blk {
        defs: vec![expected_def],
        jmps: vec![first_expected_jmp, second_expected_jmp],
        indirect_jmp_targets: vec![],
    };
    assert_eq!(second_finalized_blk.term, second_expected_blk);

    assert_eq!(
        blk,
        Blk {
            defs: vec![],
            jmps: vec![],
            indirect_jmp_targets: vec![]
        }
    );

    // Checking TIDs of blocks. Skipping first block, since TID is provided.
    let expected_tid_second_block = Tid {
        id: "artificial_blk_0x0200_1".into(),
        address: "0x0200".into(),
    };
    assert_eq!(second_finalized_blk.tid, expected_tid_second_block);

    let expected_tid_returned_block = Tid {
        id: "artificial_blk_0x0207".into(),
        address: "0x0207".into(),
    };
    assert_eq!(tid, expected_tid_returned_block);
}
