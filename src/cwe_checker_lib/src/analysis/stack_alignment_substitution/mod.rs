use apint::ApInt;

use crate::intermediate_representation::*;

fn substitute_and(exp: &mut Expression, alignment: i32, journaled_sp: i32) {
    dbg!("IN: ", &exp);
    match exp {
        Expression::BinOp { op, lhs: _, rhs } => {
            *op = BinOpType::IntSub;
            let space = dbg!(journaled_sp % alignment);
            *rhs = Box::new(Expression::Const(ApInt::from_i32(space)));
        }
        _ => todo!(),
    }
    dbg!("OUT: ", &exp);
}

fn substitute_or(mut exp: &Expression) {
    dbg!(exp);
}

fn journal_sp_value(sp: &mut i32, is_plus: bool, val: &Expression) {
    match val {
        Expression::Const(con) => {
            if is_plus {
                *sp += con.try_to_i32().unwrap()
            } else {
                *sp -= con.try_to_i32().unwrap()
            }
        }
        _ => todo!(),
    }
}

pub fn substitute_and_on_stackpointer(project: &mut Project) {
    let sp_alignment = match project.cpu_architecture.as_str() {
        "x86_32" => 16,
        "x86_64" => 16,
        "arm32" => 4,
        _ => 0,
    };

    let mut journaled_sp = 10000000;

    for sub in project.program.term.subs.values_mut() {
        for blk in sub.term.blocks.iter_mut() {
            for def in blk.term.defs.iter_mut() {
                if let Def::Assign { var, value } = &mut def.term {
                    if *var == project.stack_pointer_register {
                        match value {
                            Expression::BinOp { op, lhs, rhs } => {
                                if *lhs
                                    == Box::new(Expression::Var(
                                        project.stack_pointer_register.clone(),
                                    ))
                                {
                                    match op {
                                        BinOpType::IntAdd => {
                                            journal_sp_value(&mut journaled_sp, true, rhs)
                                        }
                                        BinOpType::IntSub => {
                                            journal_sp_value(&mut journaled_sp, false, rhs)
                                        }
                                        BinOpType::IntAnd => {
                                            substitute_and(value, sp_alignment, journaled_sp)
                                        }
                                        BinOpType::IntOr => println!("{:?} or {:?}", lhs, rhs),
                                        _ => todo!(),
                                    }
                                }
                            }
                            _ => (), // Vereinfachung!
                        }
                    }
                }
            }
        }
    }
}
