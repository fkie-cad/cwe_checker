use super::*;
use std::borrow::BorrowMut;

/// Creates a x64 or ARM32 Project for easy addidion of assignments.
fn setup(mut defs: Vec<Term<Def>>, is_x64: bool) -> Project {
    let mut proj = match is_x64 {
        true => Project::mock_x64(),
        false => Project::mock_arm32(),
    };

    let mut blk = Blk::mock();
    blk.term.defs.append(defs.as_mut());
    let mut sub = Sub::mock("Sub");
    sub.term.blocks.push(blk);
    proj.program.term.subs.insert(Tid::new("sub_tid"), sub);

    proj
}

#[test]
/// Tests the return of log messages for all alignments, including unexpected alignments for x64 and arm32.
fn unexpected_alignment() {
    for i in 0..31 {
        // case x64
        let def_x64 = vec![Def::assign(
            "tid1",
            Project::mock_x64().stack_pointer_register.clone(),
            Expression::BinOp {
                op: BinOpType::IntAnd,
                lhs: Box::new(Expression::Var(
                    Project::mock_x64().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(
                    0xFFFFFFFF << i,
                ))),
            },
        )];
        let mut proj_x64 = setup(def_x64, true);
        let log = substitute_and_on_stackpointer(proj_x64.borrow_mut());
        if 2_i32.pow(i) == 16 {
            assert!(log.is_none());
        } else {
            assert!(log.is_some());
            for msg in log.unwrap() {
                assert!(msg.text.contains("Unexpected alignment"));
            }
        }

        // case ARM32
        let def_arm = vec![Def::assign(
            "tid1",
            Project::mock_arm32().stack_pointer_register.clone(),
            Expression::BinOp {
                op: BinOpType::IntAnd,
                lhs: Box::new(Expression::Var(
                    Project::mock_arm32().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(
                    0xFFFFFFFF << i,
                ))),
            },
        )];
        let mut proj_arm = setup(def_arm, false);
        let log = substitute_and_on_stackpointer(proj_arm.borrow_mut());
        if 2_i32.pow(i) == 4 {
            assert!(log.is_none());
        } else {
            assert!(log.is_some());
            for msg in log.unwrap() {
                assert!(msg.text.contains("Unexpected alignment"));
            }
        }
    }
}

#[test]
/// Tests the substituted offset meets the alignment for x64. Tests only the logical AND case.
fn compute_correct_offset_x64() {
    for i in 0..=33 {
        let sub_from_sp = Def::assign(
            "tid_alter_sp",
            Project::mock_x64().stack_pointer_register.clone(),
            Expression::minus(
                Expression::Var(Project::mock_x64().stack_pointer_register.clone()),
                Expression::const_from_apint(ApInt::from_u64(i)),
            ),
        );

        let byte_alignment_as_and = Def::assign(
            "tid_to_be_substituted",
            Project::mock_x64().stack_pointer_register.clone(),
            Expression::BinOp {
                op: BinOpType::IntAnd,
                lhs: Box::new(Expression::Var(
                    Project::mock_x64().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                    0xFFFFFFFF_FFFFFFFF << 4, // 16 Byte alignment
                ))),
            },
        );
        let mut proj = setup(
            vec![sub_from_sp.clone(), byte_alignment_as_and.clone()],
            true,
        );
        let log = substitute_and_on_stackpointer(proj.borrow_mut());
        for sub in proj.program.term.subs.into_values() {
            for blk in sub.term.blocks {
                for def in blk.term.defs {
                    if def.tid == byte_alignment_as_and.tid.clone() {
                        let expected_offset: u64 = match i % 16 {
                            0 => 0,
                            _ => (16 - (i % 16)).into(),
                        };
                        // translated alignment as substraction
                        let expected_def = Def::Assign {
                            var: proj.stack_pointer_register.clone(),
                            value: Expression::BinOp {
                                op: BinOpType::IntSub,
                                lhs: Box::new(Expression::Var(proj.stack_pointer_register.clone())),
                                rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                                    expected_offset,
                                ))),
                            },
                        };
                        assert_eq!(expected_def, def.term);
                        assert!(log.is_none());
                    }
                }
            }
        }
    }
}

#[test]
/// Tests the substituted offset meets the alignment for arm32. Tests only the logical AND case.
fn compute_correct_offset_arm32() {
    for i in 0..=33 {
        let sub_from_sp = Def::assign(
            "tid_alter_sp",
            Project::mock_arm32().stack_pointer_register.clone(),
            Expression::minus(
                Expression::Var(Project::mock_arm32().stack_pointer_register.clone()),
                Expression::const_from_apint(ApInt::from_u32(i)),
            ),
        );
        let byte_alignment_as_and = Def::assign(
            "tid_to_be_substituted",
            Project::mock_arm32().stack_pointer_register.clone(),
            Expression::BinOp {
                op: BinOpType::IntAnd,
                lhs: Box::new(Expression::Var(
                    Project::mock_arm32().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(
                    0xFFFFFFFF << 2, // 4 Byte alignment
                ))),
            },
        );
        let mut proj = setup(
            vec![sub_from_sp.clone(), byte_alignment_as_and.clone()],
            false,
        );
        let log = substitute_and_on_stackpointer(proj.borrow_mut());
        for sub in proj.program.term.subs.into_values() {
            for blk in sub.term.blocks {
                for def in blk.term.defs {
                    if def.tid == byte_alignment_as_and.tid.clone() {
                        let expected_offset = match i % 4 {
                            0 => 0,
                            _ => 4 - (i % 4),
                        };
                        // translated alignment as substraction
                        let expected_def = Def::Assign {
                            var: proj.stack_pointer_register.clone(),
                            value: Expression::BinOp {
                                op: BinOpType::IntSub,
                                lhs: Box::new(Expression::Var(proj.stack_pointer_register.clone())),
                                rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(
                                    expected_offset,
                                ))),
                            },
                        };
                        assert_eq!(expected_def, def.term);
                        assert!(log.is_none());
                    }
                }
            }
        }
    }
}

#[test]
/// Checks behaviour on supported and unsupported binary operations.
fn check_bin_operations() {
    for biopty in vec![
        BinOpType::Piece,
        BinOpType::IntAdd,
        BinOpType::IntSub,
        BinOpType::IntAnd,
        BinOpType::IntOr,
    ] {
        let unsupported_def_x64 = Def::assign(
            "tid_to_be_substituted",
            Project::mock_x64().stack_pointer_register.clone(),
            Expression::BinOp {
                op: biopty,
                lhs: Box::new(Expression::Var(
                    Project::mock_x64().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_i32(0)),
            },
        );
        let unsupported_def_arm32 = Def::assign(
            "tid_to_be_substituted",
            Project::mock_arm32().stack_pointer_register.clone(),
            Expression::BinOp {
                op: biopty,
                lhs: Box::new(Expression::Var(
                    Project::mock_arm32().stack_pointer_register.clone(),
                )),
                rhs: Box::new(Expression::const_from_i32(0)),
            },
        );
        let mut proj_x64 = setup(vec![unsupported_def_x64.clone()], true);
        let log_x64 = substitute_and_on_stackpointer(proj_x64.borrow_mut());
        let mut proj_arm32 = setup(vec![unsupported_def_arm32.clone()], false);
        let log_arm32 = substitute_and_on_stackpointer(proj_arm32.borrow_mut());

        for log in vec![log_arm32, log_x64] {
            match biopty {
                BinOpType::IntAnd => {
                    assert_eq!(log.clone().unwrap().len(), 1);
                    assert!(log
                        .unwrap()
                        .pop()
                        .unwrap()
                        .text
                        .contains("Unexpected alignment"));
                }
                BinOpType::IntAdd | BinOpType::IntSub => {
                    assert!(log.is_none())
                }

                _ => {
                    assert_eq!(log.clone().unwrap().len(), 1);
                    assert!(log
                        .unwrap()
                        .pop()
                        .unwrap()
                        .text
                        .contains("Unsubstitutable Operation on SP"));
                }
            }
        }
    }
}

#[test]
/// Checks if the substitution on logical operations ends if an unsubstitutable operation occured.
fn substitution_ends_if_unsubstituable() {
    let alignment_16_byte_as_and = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntAnd,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                0xFFFFFFFF_FFFFFFFF << 4, // 16 Byte alignment
            ))),
        },
    );

    let unsubstitutable = Def::assign(
        "tid_unsubstitutable",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_i64(0)),
        },
    );
    let mut proj = setup(
        vec![
            alignment_16_byte_as_and.clone(),
            unsubstitutable.clone(),
            alignment_16_byte_as_and.clone(),
        ],
        true,
    );
    let log = substitute_and_on_stackpointer(proj.borrow_mut());

    assert!(log.is_some());
    assert!(log
        .unwrap()
        .pop()
        .unwrap()
        .text
        .contains("Unsubstitutable Operation on SP"));

    let exp_16_byte_alignment_substituted = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntSub,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(0))),
        },
    );

    for sub in proj.program.term.subs.into_values() {
        for blk in sub.term.blocks {
            assert_eq!(
                blk.term.defs,
                vec![
                    exp_16_byte_alignment_substituted.clone(),
                    unsubstitutable.clone(),
                    alignment_16_byte_as_and.clone()
                ]
            );
        }
    }
}

#[test]
/// Tests if the substitution supports commutativity of the expression.
fn supports_commutative_and() {
    let var_and_bitmask = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntAnd,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                0xFFFFFFFF_FFFFFFFF << 4, // 16 Byte alignment
            ))),
        },
    );
    let bitmask_and_var = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntAnd,
            lhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                0xFFFFFFFF_FFFFFFFF << 4, // 16 Byte alignment
            ))),
            rhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
        },
    );

    let mut proj = setup(vec![bitmask_and_var, var_and_bitmask], true);
    let log = substitute_and_on_stackpointer(proj.borrow_mut());
    assert!(log.is_none());

    let expected_def = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntSub,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(0))),
        },
    );

    for sub in proj.program.term.subs.into_values() {
        for blk in sub.term.blocks {
            for def in blk.term.defs {
                assert_eq!(def, expected_def);
            }
        }
    }
}
#[test]
/// Some functions have leading blocks without any defs. This might be due to `endbr`-like instructions.
/// We skip those empty blocks and start substituting for rhe first non-empty block.
fn skips_empty_blocks() {
    let sub_from_sp = Def::assign(
        "tid_alter_sp",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::minus(
            Expression::Var(Project::mock_x64().stack_pointer_register.clone()),
            Expression::const_from_apint(ApInt::from_u64(1)),
        ),
    );

    let byte_alignment_as_and = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::BinOp {
            op: BinOpType::IntAnd,
            lhs: Box::new(Expression::Var(
                Project::mock_x64().stack_pointer_register.clone(),
            )),
            rhs: Box::new(Expression::const_from_apint(ApInt::from_u64(
                0xFFFFFFFF_FFFFFFFF << 4, // 16 Byte alignment
            ))),
        },
    );
    // get project with empty block
    let mut proj = setup(vec![], true);
    // add jmp
    proj.program
        .term
        .subs
        .get_mut(&Tid::new("sub_tid"))
        .unwrap()
        .term
        .blocks[0]
        .term
        .jmps
        .push(Term {
            tid: Tid::new("tid"),
            term: Jmp::Branch(Tid::new("not_empty_blk")),
        });

    let mut blk = Blk::mock_with_tid("not_empty_blk");
    blk.term.defs.push(sub_from_sp.clone());
    blk.term.defs.push(byte_alignment_as_and.clone());

    // add block with substitutional def
    proj.program
        .term
        .subs
        .get_mut(&Tid::new("sub_tid"))
        .unwrap()
        .term
        .blocks
        .push(blk);

    let expected_def = Def::assign(
        "tid_to_be_substituted",
        Project::mock_x64().stack_pointer_register.clone(),
        Expression::minus(
            Expression::Var(Project::mock_x64().stack_pointer_register.clone()),
            Expression::const_from_apint(ApInt::from_u64(15)),
        ),
    );

    substitute_and_on_stackpointer(&mut proj);

    assert_eq!(
        proj.program
            .term
            .subs
            .get(&Tid::new("sub_tid"))
            .unwrap()
            .term
            .blocks[1]
            .term
            .defs,
        vec![sub_from_sp.clone(), expected_def]
    );
}

#[test]
fn skip_busy_loop() {
    let mut proj = setup(vec![], true);
    proj.program
        .term
        .subs
        .get_mut(&Tid::new("sub_tid"))
        .unwrap()
        .term
        .blocks[0]
        .term
        .jmps
        .push(Jmp::branch("jmp_to_1st_blk", "block"));

    assert_eq!(
        get_first_blk_with_defs(
            &proj
                .program
                .term
                .subs
                .get_mut(&Tid::new("sub_tid"))
                .unwrap()
                .term
        ),
        None
    );
}
