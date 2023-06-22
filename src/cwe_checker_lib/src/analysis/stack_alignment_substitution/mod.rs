//! Substitutes stack pointer alignment operations utilising logical AND with an arithmetic SUB operation.
//!
//! The first basic block of every function is searched for a logical AND operation on the stack pointer.
//! By journaling changes to the stack pointer an offset is calculated which is going to be used to alter the operation
//! into a subtraction.
//!
//! # Log Messages
//! Following cases trigger log messages:
//! - alignment is untypical for the architecture
//! - the argument for the AND operation is not a constant
//! - an operation alters the stack pointer, which can not be journaled.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
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

    if let Expression::BinOp { op, lhs, rhs } = exp {
        match (&**lhs, &**rhs) {
            (Expression::Var(sp), Expression::Const(bitmask))
            | (Expression::Const(bitmask), Expression::Var(sp)) => {
                if let BinOpType::IntAnd = op {
                    if ApInt::try_to_i64(&ApInt::into_negate(bitmask.clone())).unwrap()
                        != expected_alignment
                    {
                        log.push(LogMessage::new_info("Unexpected alignment").location(tid));
                    }
                    let offset =
                        *journaled_sp - (*journaled_sp & bitmask.clone().try_to_i64().unwrap());
                    let sp = sp.clone();
                    *op = BinOpType::IntSub;

                    *rhs = Box::new(Expression::Const(
                        (ApInt::from_i64(offset)).into_resize_unsigned(bitmask.bytesize()),
                    ));
                    *lhs = Box::new(Expression::Var(sp));
                } else {
                    log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
                };
            }
            _ => log.push(
                LogMessage::new_info(
                    "Unsubstitutable Operation on SP. Operants are not register and constant.",
                )
                .location(tid),
            ),
        }
    } else {
        log.push(LogMessage::new_info("Unsubstitutable Operation on SP").location(tid))
    }
    log
}

/// Updates current stackpointer value by given Constant.
fn journal_sp_value(
    journaled_sp: &mut i64,
    is_plus: bool,
    (rhs, lhs): (&Expression, &Expression),
    sp_register: &Variable,
) -> Result<()> {
    match (rhs, lhs) {
        (Expression::Var(sp), Expression::Const(constant))
        | (Expression::Const(constant), Expression::Var(sp)) => {
            if sp == sp_register {
                match is_plus {
                    true => *journaled_sp += constant.try_to_i64().unwrap(),
                    false => *journaled_sp -= constant.try_to_i64().unwrap(),
                }
                Ok(())
            } else {
                Err(anyhow!("Input not stackpointer register and constant."))
            }
        }
        _ => Err(anyhow!("Input not register and constant.")),
    }
}

/// Returns the tid of the target of the first Jmp::Branch of the provided block.
fn get_first_branch_tid(blk: &Term<Blk>) -> Option<&Tid> {
    if let Some(jmp) = blk.term.jmps.get(0) {
        if let Jmp::Branch(jump_to_blk) = &jmp.term {
            return Some(jump_to_blk);
        }
    }
    None
}

/// Returns the index of the first block with non-empty defs.
/// Blocks are iterated according by considering their first `Jmp::Branch`.
/// If a block is revisited, `None` is returned.
fn get_first_blk_with_defs(sub: &Sub) -> Option<usize> {
    let blocks = &sub.blocks;
    if let Some(start_blk) = blocks.first() {
        let mut visited = HashSet::new();
        let mut blk = start_blk;

        'search_loop: while blk.term.defs.is_empty() {
            if let Some(target_tid) = get_first_branch_tid(blk) {
                if !visited.contains(&blk.tid) {
                    visited.insert(&blk.tid);

                    // try find this target
                    for (index, target_blk) in blocks.iter().enumerate() {
                        if &target_blk.tid == target_tid {
                            if !target_blk.term.defs.is_empty() {
                                return Some(index);
                            } else {
                                // continue with new block
                                blk = target_blk;
                                continue 'search_loop;
                            }
                        }
                    }
                    // did not find target
                    return None;
                } else {
                    // busy loop
                    return None;
                }
            } else {
                // did not find branch in block
                return None;
            }
        }
        // first block was not empty
        return Some(0);
    }
    None
}

/// Substitutes logical AND on the stackpointer register by SUB.
/// Expressions are changed to use constants w.r.t the provided bit mask.
pub fn substitute_and_on_stackpointer(project: &mut Project) -> Option<Vec<LogMessage>> {
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
        if let Some(index) = get_first_blk_with_defs(&sub.term) {
            let blk = &mut sub.term.blocks[index];
            for def in blk.term.defs.iter_mut() {
                if let Def::Assign { var, value } = &mut def.term {
                    if *var == project.stack_pointer_register {
                        if let Expression::BinOp { op, lhs, rhs } = value {
                            match op {
                                BinOpType::IntAdd => {
                                    if journal_sp_value(
                                        journaled_sp,
                                        true,
                                        (lhs, rhs),
                                        &project.stack_pointer_register,
                                    )
                                    .is_err()
                                    {
                                        continue 'sub_loop;
                                    }
                                }
                                BinOpType::IntSub => {
                                    if journal_sp_value(
                                        journaled_sp,
                                        false,
                                        (lhs, rhs),
                                        &project.stack_pointer_register,
                                    )
                                    .is_err()
                                    {
                                        continue 'sub_loop;
                                    }
                                }
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
                        } else {
                            log.push(
                                LogMessage::new_info("Unexpected assignment on SP")
                                    .location(def.tid.clone()),
                            );
                            continue 'sub_loop;
                        }
                    }
                }
            }
        }
    }
    if log.is_empty() {
        return None;
    }
    Some(log)
}

#[cfg(test)]
mod tests;
