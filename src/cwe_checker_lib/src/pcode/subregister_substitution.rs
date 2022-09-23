use super::RegisterProperties;
use crate::intermediate_representation::{BinOpType, Blk, Def, Expression, Jmp, Variable};
use crate::prelude::*;
use std::collections::HashMap;
use std::iter::Peekable;
use std::ops::Deref;

// TODO: Recognize the zero-extend-case in the next Def!

pub fn replace_subregister_in_block(block: & mut Term<Blk>,
register_map: &HashMap<&String, &RegisterProperties>
) {
    // Substitute subregisters in expressions contained in jump instructions
    for jump in block.term.jmps.iter_mut() {
        replace_subregister_in_jump(jump, register_map);
    };
    // Substitute subregisters in Def instructions
    let new_defs = SubregisterSubstitutionBuilder::compute_replacement_defs_for_block(block, register_map);
    block.term.defs = new_defs;
}

struct SubregisterSubstitutionBuilder<'a> {
    register_map: &'a HashMap<&'a String, &'a RegisterProperties>,
    input_iter: Peekable<std::slice::Iter<'a, Term<Def>>>,
    output_defs: Vec<Term<Def>>,
}

impl<'a> SubregisterSubstitutionBuilder<'a> {
    fn new(
        block: &'a Term<Blk>,
        register_map: &'a HashMap<&'a String, &'a RegisterProperties>,
    ) -> Self {
        SubregisterSubstitutionBuilder {
            register_map,
            input_iter: block.term.defs.iter().peekable(),
            output_defs: Vec::new(),
        }
    }

    pub fn compute_replacement_defs_for_block(
        block: &'a mut Term<Blk>,
        register_map: &'a HashMap<&'a String, &'a RegisterProperties>,
    ) -> Vec<Term<Def>> {
        let mut substitution_builder = Self::new(block, register_map);
        while let Some(def) = substitution_builder.input_iter.next() {
            substitution_builder.replace_subregister(def);
        }
        substitution_builder.output_defs
    }

    fn replace_subregister(&mut self, def: &Term<Def>) {
        let mut def = def.clone();
        match &mut def.term {
            Def::Assign {
                var: _,
                value: expr,
            }
            | Def::Load {
                var: _,
                address: expr,
            } => {
                *expr = replace_input_subregister(expr.clone(), self.register_map);
            }
            Def::Store { address, value } => {
                *address = replace_input_subregister(address.clone(), self.register_map);
                *value = replace_input_subregister(value.clone(), self.register_map);
            }
        }
        self.replace_output_subregister(def);
    }

    fn replace_output_subregister(&mut self, def: Term<Def>) {
        match &def.term {
            Def::Assign { var, value } => {
                if let Some(register) = self.register_map.get(&var.name) {
                    if var.name != register.base_register || var.size < register.size {
                        // The register is not a base register and should be replaced.
                        if self.is_next_def_cast_to_base_register(var) {
                            let mut output = self.input_iter.next().unwrap().clone();
                            match &mut output.term {
                                Def::Assign {
                                    var,
                                    value: output_expr,
                                } => {
                                    output_expr.substitute_input_var(var, value);
                                }
                                _ => panic!(),
                            }
                            self.output_defs.push(output);
                            return;
                        } else {
                            let base_register: &RegisterProperties =
                                self.register_map.get(&register.base_register).unwrap();
                            let output_var: Variable = base_register.into();
                            let output_expression =
                                piece_base_register_assignment_expression_together(
                                    value,
                                    base_register,
                                    register,
                                );
                            self.output_defs.push(Term {
                                tid: def.tid.clone(),
                                term: Def::Assign {
                                    var: output_var,
                                    value: output_expression,
                                },
                            });
                            return;
                        }
                    }
                }
            }
            Def::Load { var, address } => {
                if let Some(register) = self.register_map.get(&var.name) {
                    if var.name != register.base_register || var.size < register.size {
                        // The register is not a base register and should be replaced.
                        // We need two replacement defs: One is a load into a temporary register
                        // and the second is a cast to the base register.
                        let temp_reg = Variable {
                            name: "loaded_value".to_string(),
                            size: var.size,
                            is_temp: true,
                        };
                        self.output_defs.push(Term {
                            tid: def.tid.clone(),
                            term: Def::Load {
                                var: temp_reg.clone(),
                                address: address.clone(),
                            },
                        });
                        if self.is_next_def_cast_to_base_register(var) {
                            let mut cast_to_base_def = self.input_iter.next().unwrap().clone();
                            if let Def::Assign { value, .. } = &mut cast_to_base_def.term {
                                value.substitute_input_var(var, &Expression::Var(temp_reg));
                            } else {
                                panic!()
                            }
                            self.output_defs.push(cast_to_base_def);
                        } else {
                            let base_register: &RegisterProperties =
                                self.register_map.get(&register.base_register).unwrap();
                            self.output_defs.push(Term {
                                tid: def.tid.clone().with_id_suffix("_cast_to_base"),
                                term: Def::Assign {
                                    var: base_register.into(),
                                    value: piece_base_register_assignment_expression_together(
                                        &Expression::Var(temp_reg),
                                        base_register,
                                        register,
                                    ),
                                },
                            });
                        }
                        return;
                    }
                }
            }
            Def::Store { address, value } => (),
        }
        // We did not need to modify the Def
        self.output_defs.push(def);
    }

    fn is_next_def_cast_to_base_register(&mut self, input_var: &Variable) -> bool {
        if let Some(peeked_def) = self.input_iter.peek() {
            match &peeked_def.term {
                Def::Assign { var, value } => {
                    if let (Some(reg), Some(input_reg)) = (
                        self.register_map.get(&var.name),
                        self.register_map.get(&input_var.name),
                    ) {
                        match value {
                            Expression::Cast { arg, .. } => match arg.deref() {
                                Expression::Var(cast_var) if cast_var == input_var => {
                                    if input_reg.register != input_reg.base_register
                                        && input_reg.base_register == reg.register
                                    {
                                        return true;
                                    }
                                }
                                _ => (),
                            },
                            _ => (),
                        }
                    }
                }
                _ => (),
            }
        }

        false
    }
}

fn replace_subregister_in_jump(jump: &mut Term<Jmp>, register_map: &HashMap<&String, &RegisterProperties>) {
    match &mut jump.term {
        Jmp::BranchInd(expr)
        | Jmp::CBranch {
            condition: expr, ..
        }
        | Jmp::CallInd { target: expr, .. }
        | Jmp::Return(expr) => {
            *expr = replace_input_subregister(expr.clone(), register_map);
        }
        Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
    }
}

fn replace_input_subregister(
    mut expression: Expression,
    register_map: &HashMap<&String, &RegisterProperties>,
) -> Expression {
    let mut replacement_pairs = Vec::new();
    for var in expression.input_vars() {
        if let Some(register) = register_map.get(&var.name) {
            if var.name != register.base_register || var.size < register.size {
                // The register is not a base register and should be replaced.
                let target_size = var.size;
                let replacement_expr = create_subpiece_from_sub_register(
                    register.base_register.clone(),
                    target_size,
                    register.lsb,
                    register_map,
                );
                replacement_pairs.push((var.clone(), replacement_expr));
            }
        }
    }
    for (var, replacement_expr) in replacement_pairs {
        expression.substitute_input_var(&var, &replacement_expr);
    }
    expression
}

/// This function creates a SUBPIECE expression
/// from a sub_register containing the corresponding base register.
fn create_subpiece_from_sub_register(
    base: String,
    size: ByteSize,
    lsb: ByteSize,
    register_map: &HashMap<&String, &RegisterProperties>,
) -> Expression {
    Expression::Subpiece {
        low_byte: lsb,
        size,
        arg: Box::new(Expression::Var(Variable {
            name: base.clone(),
            size: register_map.get(&base).unwrap().size,
            is_temp: false,
        })),
    }
}

/// Consider an assignment of the form `sub-register = input_expression`.
/// Then this function pieces together an assignment expression for the base register
/// out of the input expression and those parts of the base register
/// that are not part of the sub-register (i.e. that are not overwritten by the sub-register assignment).
fn piece_base_register_assignment_expression_together(
    input_expression: &Expression,
    output_base_register: &RegisterProperties,
    sub_register: &RegisterProperties,
) -> Expression {
    let base_size: ByteSize = output_base_register.size;
    let base_name: &String = &output_base_register.register;
    let sub_size: ByteSize = sub_register.size;
    let sub_lsb: ByteSize = sub_register.lsb;

    let base_subpiece = Box::new(Expression::Var(Variable {
        name: base_name.clone(),
        size: base_size,
        is_temp: false,
    }));

    if sub_register.lsb > ByteSize::new(0) && sub_register.lsb + sub_register.size == base_size {
        // Build PIECE as PIECE(lhs: sub_register, rhs: low subpiece)
        return Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(input_expression.clone()),
            rhs: Box::new(Expression::Subpiece {
                low_byte: ByteSize::new(0),
                size: sub_lsb,
                arg: base_subpiece,
            }),
        };
    } else if sub_register.lsb > ByteSize::new(0) {
        // Build PIECE as PIECE(lhs:PIECE(lhs:higher subpiece, rhs:sub register), rhs:lower subpiece)
        return Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::BinOp {
                op: BinOpType::Piece,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: sub_lsb + sub_size,
                    size: base_size - (sub_lsb + sub_size),
                    arg: base_subpiece.clone(),
                }),
                rhs: Box::new(input_expression.clone()),
            }),
            rhs: Box::new(Expression::Subpiece {
                low_byte: ByteSize::new(0),
                size: sub_lsb,
                arg: base_subpiece,
            }),
        };
    } else {
        // Build PIECE as PIECE(lhs: high subpiece, rhs: sub register)
        return Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::Subpiece {
                low_byte: sub_size,
                size: base_size - sub_size,
                arg: base_subpiece,
            }),
            rhs: Box::new(input_expression.clone()),
        };
    }
}
