//! Substitutes stack pointer alignment operations utilising logical AND with an arithmetic SUB operation.
//!
//! The first basic block of every function is searched for a logical AND operation on the stack pointer.
//! By journeling changes to the stack pointer an offset is calculated which is going to be used to alter the operation
//! into a subtraction.
//!
//! # Log Messages
//! Following cases trigger log messages:
//! - alignment is untypical for the architecture
//! - the argument for the AND operation is not a constant
//! - an operation alters the stack pointer, which can not be journeled.

use apint::ApInt;
use itertools::Itertools;

use crate::{intermediate_representation::*, utils::log::LogMessage};

/// Substitutes AND operation by SUB operation with calculated constants.
/// Constants are derived by a journaled stackpointer value and the bitmask provided by the operation.
fn substitute(
    exp: &mut Expression,
    expected_alignment: i64,
    journaled_sp: &mut i64,
    tid: Tid,
) -> Vec<LogMessage> {
    let mut log: Vec<LogMessage> = vec![];

    if let Expression::BinOp { op, lhs: _, rhs } = exp {
        if let Expression::Const(bitmask) = &**rhs {
            if let BinOpType::IntAnd = op {
                let alignment = ApInt::try_to_i64(&ApInt::into_negate(bitmask.clone())).unwrap();
                let offset = journaled_sp.checked_rem_euclid(alignment).unwrap_or(0);
                *op = BinOpType::IntSub;
                *rhs = Box::new(Expression::Const(
                    (ApInt::from_i64(offset)).into_resize_unsigned(bitmask.bytesize()),
                ));
                if alignment != expected_alignment {
                    log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                }
            } else {
                log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
            };
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
fn journal_sp_value(sp: &mut i64, is_plus: bool, val: &Expression) {
    if let Expression::Const(con) = val {
        if is_plus {
            *sp += con.try_to_i64().unwrap()
        } else {
            *sp -= con.try_to_i64().unwrap()
        }
    }
}

/// Substitutes logical AND on the stackpointer register by SUB.
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

    'sub_loop: for sub in project.program.term.subs.values_mut() {
        let journaled_sp: &mut i64 = &mut 0;
        // only for the first block SP can be reasonable tracked
        if let Some(blk) = sub.term.blocks.first_mut() {
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
                                        log.append(&mut msg);
                                        if !log
                                            .iter()
                                            .filter(|x| {
                                                x.text.contains("Unsubstitutable Operation on SP")
                                            })
                                            .collect_vec()
                                            .is_empty()
                                        {
                                            // Lost track of SP
                                            continue 'sub_loop;
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
