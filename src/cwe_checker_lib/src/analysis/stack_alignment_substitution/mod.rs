use apint::ApInt;
use itertools::Itertools;

use crate::{intermediate_representation::*, utils::log::LogMessage};

/// Substitutes AND (OR) operation by SUB (ADD) operation with calculated constants.
/// Constants are derived by a journaled stackpointer value and the bitmask provided by the operation.
fn substitute(
    exp: &mut Expression,
    expected_alignment: u64,
    journaled_sp: &mut u64,
    tid: Tid,
) -> Vec<LogMessage> {
    let mut log: Vec<LogMessage> = vec![];

    if let Expression::BinOp { op, lhs: _, rhs } = exp {
        if let Expression::Const(bitmask) = &**rhs {
            let alignment = ApInt::try_to_u64(&ApInt::into_negate(bitmask.clone())).unwrap();

            let offset = journaled_sp.checked_rem(alignment).unwrap_or(0);

            match op {
                BinOpType::IntAnd => {
                    *op = BinOpType::IntSub;
                    *journaled_sp -= offset;
                    if alignment != expected_alignment {
                        log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                    }
                }
                BinOpType::IntOr => {
                    *op = BinOpType::IntAdd;
                    *journaled_sp += offset;
                    if alignment != expected_alignment {
                        log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                    }
                }
                _ => {
                    log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
                }
            };
            *rhs = Box::new(Expression::Const(
                (ApInt::from_u64(offset)).into_resize_unsigned(bitmask.bytesize()),
            ));
        } else {
            log.push(
                LogMessage::new_info(
                    "Unsubstitutable Operation on SP. Right side is not a constant",
                )
                .location(tid),
            )
        }
    } else {
        log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
    }
    log
}

/// Updates current stackpointer value by given Constant.
fn journal_sp_value(sp: &mut u64, is_plus: bool, val: &Expression) {
    match val {
        Expression::Const(con) => {
            if is_plus {
                *sp += con.try_to_u64().unwrap()
            } else {
                *sp -= con.try_to_u64().unwrap()
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

    let mut log: Vec<LogMessage> = vec![];

    for sub in project.program.term.subs.values_mut() {
        let journaled_sp: &mut u64 = &mut 10000000; // 128-Byte aligned
                                                    // only for the first block SP can be reasonable tracked
        'blk_loop: for blk in sub.term.blocks.first_mut() {
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
                                    _ => {
                                        let mut msg = substitute(
                                            value,
                                            sp_alignment,
                                            journaled_sp,
                                            def.tid.clone(),
                                        );
                                        log.append(msg.as_mut());
                                        if !msg
                                            .into_iter()
                                            .filter(|x| {
                                                x.text.contains("Unsubstitutable Operation on SP")
                                            })
                                            .collect_vec()
                                            .is_empty()
                                        {
                                            // Lost track of SP
                                            break 'blk_loop;
                                        }
                                    }
                                }
                            }
                        } else {
                            log.push(
                                LogMessage::new_info("Unexpected assignment on SP")
                                    .location(def.tid.clone()),
                            )
                        }
                    }
                }
            }
        }
    }
    log
}

#[cfg(test)]
mod tests;
