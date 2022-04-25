use apint::ApInt;

use crate::{intermediate_representation::*, utils::log::LogMessage};

/// Substitutes AND (OR) operation by SUB (ADD) operation with calculated constants.
/// Constants are derived by a journaled stackpointer value and the bitmask provided by the operation.
fn substitute(
    exp: &mut Expression,
    alignment: u32,
    journaled_sp: &mut u32,
    tid: Tid,
) -> Vec<LogMessage> {
    let mut log: Vec<LogMessage> = vec![];

    if let Expression::BinOp { op, lhs: _, rhs } = exp {
        if let Expression::Const(a) = &**rhs {
            let bitmask: u32 = ApInt::try_to_u32(&ApInt::into_negate(a.clone())).unwrap();

            let offset = journaled_sp.checked_rem(bitmask).unwrap_or(0);

            match op {
                BinOpType::IntAnd => {
                    *op = BinOpType::IntSub;
                    *journaled_sp -= offset;
                    if bitmask != alignment {
                        log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                    }
                }
                BinOpType::IntOr => {
                    *op = BinOpType::IntAdd;
                    *journaled_sp += offset;
                    if bitmask != alignment {
                        log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                    }
                }
                _ => {
                    log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
                }
            };
            *rhs = Box::new(Expression::Const(ApInt::from_u32(offset)));
        }
    } else {
        log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
    }
    log
}

/// Updates current stackpointer value by given Constant.
fn journal_sp_value(sp: &mut u32, is_plus: bool, val: &Expression) {
    match val {
        Expression::Const(con) => {
            if is_plus {
                *sp += con.try_to_u32().unwrap()
            } else {
                *sp -= con.try_to_u32().unwrap()
            }
        }
        _ => todo!(),
    }
}

/// Substitutes logical AND and OR on the stackpointer register by SUB and ADD.
/// Expressions are changed to use constants w.r.t the provided bit mask.
pub fn substitute_and_on_stackpointer(project: &mut Project) -> Vec<LogMessage> {
    // for sanity check
    let sp_alignment = match project.cpu_architecture.as_str() {
        "x86_32" => 16,
        "x86_64" => 16,
        "arm32" => 4,
        _ => 0,
    };

    let journaled_sp: &mut u32 = &mut 10000000; // 128-Byte aligned
    let mut log: Vec<LogMessage> = vec![];

    for sub in project.program.term.subs.values_mut() {
        for blk in sub.term.blocks.iter_mut() {
            for def in blk.term.defs.iter_mut() {
                if let Def::Assign { var, value } = &mut def.term {
                    if *var == project.stack_pointer_register {
                        if let Expression::BinOp { op, lhs, rhs } = value {
                            if *lhs
                                == Box::new(Expression::Var(project.stack_pointer_register.clone()))
                            // Looking for operations on SP
                            {
                                match op {
                                    BinOpType::IntAdd => journal_sp_value(journaled_sp, true, rhs),
                                    BinOpType::IntSub => journal_sp_value(journaled_sp, false, rhs),
                                    _ => log.append(
                                        substitute(
                                            value,
                                            sp_alignment,
                                            journaled_sp,
                                            def.tid.clone(),
                                        )
                                        .as_mut(),
                                    ),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    log
}

#[cfg(test)]
mod tests {

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
                Expression::BinOp {
                    op: BinOpType::IntSub,
                    lhs: Box::new(Expression::Var(
                        Project::mock_x64().stack_pointer_register.clone(),
                    )),
                    rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(i))),
                },
            );
            let byte_alignment_as_and = Def::assign(
                "tid_to_be_substituted",
                Project::mock_x64().stack_pointer_register.clone(),
                Expression::BinOp {
                    op: BinOpType::IntAnd,
                    lhs: Box::new(Expression::Var(
                        Project::mock_x64().stack_pointer_register.clone(),
                    )),
                    rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(
                        0xFFFFFFFF << 4, // 16 Byte alignment
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
                            let expected_offset = match i % 16 {
                                0 => 0,
                                _ => 16 - (i % 16),
                            };
                            // translated alignment as substraction
                            let expected_def = Def::Assign {
                                var: proj.stack_pointer_register.clone(),
                                value: Expression::BinOp {
                                    op: BinOpType::IntSub,
                                    lhs: Box::new(Expression::Var(
                                        proj.stack_pointer_register.clone(),
                                    )),
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
    /// Tests the substituted offset meets the alignment for arm32. Tests only the logical AND case.
    fn compute_correct_offset_arm32() {
        for i in 0..=33 {
            let sub_from_sp = Def::assign(
                "tid_alter_sp",
                Project::mock_arm32().stack_pointer_register.clone(),
                Expression::BinOp {
                    op: BinOpType::IntSub,
                    lhs: Box::new(Expression::Var(
                        Project::mock_arm32().stack_pointer_register.clone(),
                    )),
                    rhs: Box::new(Expression::const_from_apint(ApInt::from_u32(i))),
                },
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
                                    lhs: Box::new(Expression::Var(
                                        proj.stack_pointer_register.clone(),
                                    )),
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
    /// Checks behaviour on all binary operations, mostly unsupported operations.
    fn check_all_bin_operations() {
        for biopty in vec![
            BinOpType::Piece,
            BinOpType::IntEqual,
            BinOpType::IntNotEqual,
            BinOpType::IntLess,
            BinOpType::IntSLess,
            BinOpType::IntLessEqual,
            BinOpType::IntSLessEqual,
            BinOpType::IntAdd,
            BinOpType::IntSub,
            BinOpType::IntCarry,
            BinOpType::IntSCarry,
            BinOpType::IntSBorrow,
            BinOpType::IntXOr,
            BinOpType::IntAnd,
            BinOpType::IntOr,
            BinOpType::IntLeft,
            BinOpType::IntRight,
            BinOpType::IntSRight,
            BinOpType::IntMult,
            BinOpType::IntDiv,
            BinOpType::IntRem,
            BinOpType::IntSDiv,
            BinOpType::IntSRem,
            BinOpType::BoolXOr,
            BinOpType::BoolAnd,
            BinOpType::BoolOr,
            BinOpType::FloatEqual,
            BinOpType::FloatNotEqual,
            BinOpType::FloatLess,
            BinOpType::FloatLessEqual,
            BinOpType::FloatAdd,
            BinOpType::FloatSub,
            BinOpType::FloatMult,
            BinOpType::FloatDiv,
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
}
