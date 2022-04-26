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
            assert!(log.is_empty());
        } else {
            assert!(!log.is_empty());
            for msg in log {
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
            assert!(log.is_empty());
        } else {
            assert!(!log.is_empty());
            for msg in log {
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
                        assert!(log.is_empty());
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
                        assert!(log.is_empty());
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

        for mut log in vec![log_arm32, log_x64] {
            match biopty {
                BinOpType::IntAnd | BinOpType::IntOr => {
                    assert_eq!(log.len(), 1);
                    assert!(log.pop().unwrap().text.contains("Unexpected alignment"));
                }
                BinOpType::IntAdd | BinOpType::IntSub => {
                    assert_eq!(log.len(), 0)
                }

                _ => {
                    assert_eq!(log.len(), 1);
                    assert!(log
                        .pop()
                        .unwrap()
                        .text
                        .contains("Unsubstitutable Operation on SP"));
                }
            }
        }
    }
}
