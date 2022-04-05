use apint::ApInt;

use crate::{intermediate_representation::*, utils::log::LogMessage};

/// Substitutes AND (OR) operation by SUB (ADD) operation with calculated constants.
/// Constants are derived by a journaled stackpointer value and the bitmask provided by the operation.
fn substitute(
    exp: &mut Expression,
    alignment: u32,
    mut journaled_sp: u32,
    tid: Tid,
) -> Vec<LogMessage> {
    dbg!(&journaled_sp);
    dbg!("IN: ", &exp);
    let mut log: Vec<LogMessage> = vec![];

    if let Expression::BinOp { op, lhs: _, rhs } = exp {
        if let Expression::Const(a) = &**rhs {
            let offset: u32 =
                dbg!(journaled_sp % ApInt::try_to_u32(&ApInt::into_negate(a.clone())).unwrap());
            if offset != alignment {
                log.push(LogMessage::new_info("Unexpected alignment").location(tid.clone()))
            }
            match op {
                BinOpType::IntAnd => {
                    *op = BinOpType::IntSub;
                    journaled_sp -= offset;
                }
                BinOpType::IntOr => {
                    *op = BinOpType::IntAdd;
                    journaled_sp += offset;
                }
                _ => log.push(
                    LogMessage::new_info("Unsubstitutable Operation on SP").location(tid.clone()),
                ),
            };
            *rhs = Box::new(Expression::Const(ApInt::from_u32(offset)));
        }
    } else {
        log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid.clone()))
    }

    dbg!("OUT: ", &exp);
    dbg!(&journaled_sp);
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
            dbg!(&sp);
        }
        _ => todo!(),
    }
}

/// Substitutes logical AND and OR on the stackpointer register by SUB and ADD.
/// Expressions are changed and used masks translated into constants.
pub fn substitute_and_on_stackpointer(project: &mut Project) -> Vec<LogMessage> {
    // for sanity check
    let sp_alignment = match project.cpu_architecture.as_str() {
        "x86_32" => 16,
        "x86_64" => 16,
        "arm32" => 4,
        _ => 0,
    };

    let mut journaled_sp: u32 = 10000000;
    let mut log: Vec<LogMessage> = vec![];

    for sub in project.program.term.subs.values_mut() {
        for blk in sub.term.blocks.iter_mut() {
            for def in blk.term.defs.iter_mut() {
                if let Def::Assign { var, value } = &mut def.term {
                    if *var == project.stack_pointer_register {
                        if let Expression::BinOp { op, lhs, rhs } = value {
                            if *lhs
                                == Box::new(Expression::Var(project.stack_pointer_register.clone()))
                            {
                                match op {
                                    BinOpType::IntAdd => {
                                        journal_sp_value(&mut journaled_sp, true, rhs)
                                    }
                                    BinOpType::IntSub => {
                                        journal_sp_value(&mut journaled_sp, false, rhs)
                                    }
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
    dbg!(log)
}
