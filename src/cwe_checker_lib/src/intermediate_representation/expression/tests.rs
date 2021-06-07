use super::*;

struct Setup<'a> {
    register_map: HashMap<&'a String, &'a RegisterProperties>,
    eax_name: String,
    rax_name: String,
    ecx_name: String,
    rcx_name: String,
    eax_register: RegisterProperties,
    rax_register: RegisterProperties,
    ecx_register: RegisterProperties,
    rcx_register: RegisterProperties,
    higher_byte_register: RegisterProperties,
    int_sub_expr: Expression,
    int_sub_subpiece_expr: Expression,
    eax_variable: Expression,
    rax_variable: Expression,
    rcx_variable: Expression,
}

impl<'a> Setup<'a> {
    fn new() -> Self {
        Self {
            register_map: HashMap::new(),
            eax_name: String::from("EAX"),
            rax_name: String::from("RAX"),
            ecx_name: String::from("ECX"),
            rcx_name: String::from("RCX"),
            eax_register: RegisterProperties {
                register: String::from("EAX"),
                base_register: String::from("RAX"),
                lsb: ByteSize::new(0),
                size: ByteSize::new(4),
            },
            rax_register: RegisterProperties {
                register: String::from("RAX"),
                base_register: String::from("RAX"),
                lsb: ByteSize::new(0),
                size: ByteSize::new(8),
            },
            ecx_register: RegisterProperties {
                register: String::from("ECX"),
                base_register: String::from("RCX"),
                lsb: ByteSize::new(0),
                size: ByteSize::new(4),
            },
            rcx_register: RegisterProperties {
                register: String::from("RCX"),
                base_register: String::from("RCX"),
                lsb: ByteSize::new(0),
                size: ByteSize::new(8),
            },
            higher_byte_register: RegisterProperties {
                register: String::from("AH"),
                base_register: String::from("RAX"),
                lsb: ByteSize::new(1),
                size: ByteSize::new(1),
            },
            int_sub_expr: Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Var(Variable {
                    name: String::from("EAX"),
                    size: ByteSize::new(4),
                    is_temp: false,
                })),
                rhs: Box::new(Expression::Var(Variable {
                    name: String::from("ECX"),
                    size: ByteSize::new(4),
                    is_temp: false,
                })),
            },
            int_sub_subpiece_expr: Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(Expression::Var(Variable {
                        name: String::from("RAX"),
                        size: ByteSize::new(8),
                        is_temp: false,
                    })),
                }),
                rhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(Expression::Var(Variable {
                        name: String::from("RCX"),
                        size: ByteSize::new(8),
                        is_temp: false,
                    })),
                }),
            },
            eax_variable: Expression::Var(Variable {
                name: String::from("EAX"),
                size: ByteSize::new(4),
                is_temp: false,
            }),
            rax_variable: Expression::Var(Variable {
                name: String::from("RAX"),
                size: ByteSize::new(8),
                is_temp: false,
            }),
            rcx_variable: Expression::Var(Variable {
                name: String::from("RCX"),
                size: ByteSize::new(8),
                is_temp: false,
            }),
        }
    }
}

#[test]
fn trivial_expression_substitution() {
    let setup = Setup::new();
    let mut expr = Expression::BinOp {
        op: BinOpType::IntXOr,
        lhs: Box::new(setup.rax_variable.clone()),
        rhs: Box::new(setup.rax_variable.clone()),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::Const(Bitvector::zero(ByteSize::new(8).into()))
    );
    let mut expr = Expression::BinOp {
        op: BinOpType::IntOr,
        lhs: Box::new(setup.rax_variable.clone()),
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(8).into()))),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, setup.rax_variable);

    let sub_expr = Expression::BinOp {
        lhs: Box::new(setup.rax_variable.clone()),
        op: BinOpType::IntSub,
        rhs: Box::new(setup.rcx_variable.clone()),
    };
    let mut expr = Expression::BinOp {
        op: BinOpType::IntEqual,
        lhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
        rhs: Box::new(sub_expr.clone()),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntEqual,
            rhs: Box::new(setup.rcx_variable.clone()),
        }
    );
    let mut expr = Expression::BinOp {
        op: BinOpType::IntNotEqual,
        lhs: Box::new(sub_expr.clone()),
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntNotEqual,
            rhs: Box::new(setup.rcx_variable.clone()),
        }
    );

    let mut expr = Expression::BinOp {
        lhs: Box::new(Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntLess,
            rhs: Box::new(setup.rcx_variable.clone()),
        }),
        op: BinOpType::BoolOr,
        rhs: Box::new(Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntEqual,
            rhs: Box::new(setup.rcx_variable.clone()),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(setup.rcx_variable.clone()),
        }
    );

    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(Expression::Cast {
            op: CastOpType::IntSExt,
            size: ByteSize::new(8),
            arg: Box::new(Expression::Var(Variable::mock("EAX", 4))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, Expression::Var(Variable::mock("EAX", 4)));
    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(4),
        size: ByteSize::new(4),
        arg: Box::new(Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::Var(Variable::mock("EAX", 4))),
            rhs: Box::new(Expression::Var(Variable::mock("EBX", 4))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(expr, Expression::Var(Variable::mock("EAX", 4)));
    let mut expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(2),
            size: ByteSize::new(6),
            arg: Box::new(Expression::Var(Variable::mock("RAX", 8))),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::Subpiece {
            low_byte: ByteSize::new(2),
            size: ByteSize::new(4),
            arg: Box::new(Expression::Var(Variable::mock("RAX", 8))),
        }
    );

    let mut expr = Expression::UnOp {
        op: UnOpType::BoolNegate,
        arg: Box::new(Expression::BinOp {
            lhs: Box::new(setup.rax_variable.clone()),
            op: BinOpType::IntLess,
            rhs: Box::new(setup.rcx_variable.clone()),
        }),
    };
    expr.substitute_trivial_operations();
    assert_eq!(
        expr,
        Expression::BinOp {
            lhs: Box::new(setup.rcx_variable.clone()),
            op: BinOpType::IntLessEqual,
            rhs: Box::new(setup.rax_variable.clone()),
        }
    );
}

#[test]
fn subpiece_creation() {
    let setup = Setup::new();
    let lsb = ByteSize::new(0);
    let size = ByteSize::new(4);
    let mut register_map = setup.register_map.clone();
    register_map.insert(&setup.eax_name, &setup.eax_register);
    register_map.insert(&setup.rax_name, &setup.rax_register);

    let mut expr = setup.eax_variable.clone();

    let expected_expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(setup.rax_variable.clone()),
    };

    expr.create_subpiece_from_sub_register(setup.rax_name.clone(), size, lsb, &register_map);
    assert_eq!(expr, expected_expr);
}

#[test]
fn piecing_expressions_together() {
    let setup = Setup::new();
    // Simple test:
    // Input:           EAX = INT_SUB SUBPIECE(RAX, 0, 4), SUBPIECE(RCX, 0, 4)
    // Expected Output: RAX = PIECE(SUBPIECE(RAX, 4, 4), INT_SUB SUBPIECE(RAX, 0, 4), SUBPIECE(RCX, 0, 4))
    let mut expr = setup.int_sub_subpiece_expr.clone();

    let expected_expr = Expression::BinOp {
        op: BinOpType::Piece,
        lhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(4),
            size: ByteSize::new(4),
            arg: Box::new(setup.rax_variable.clone()),
        }),
        rhs: Box::new(setup.int_sub_subpiece_expr.clone()),
    };

    // More complex test:
    // Input:           EAX = INT_SUB SUBPIECE(RAX, 1, 1), 0:1;
    // Expected Output: RAX = PIECE[ PIECE(SUBPIECE(RAX, 2, 6), INT_SUB SUBPIECE(RAX, 1, 1)), SUBPIECE(RAX, 0, 1) ]
    let mut higher_byte_exp = Expression::BinOp {
        op: BinOpType::IntSub,
        lhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(1),
            size: ByteSize::new(1),
            arg: Box::new(setup.rax_variable.clone()),
        }),
        rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
    };

    let expected_higher_byte_expr = Expression::BinOp {
        op: BinOpType::Piece,
        lhs: Box::new(Expression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(Expression::Subpiece {
                low_byte: ByteSize::new(2),
                size: ByteSize::new(6),
                arg: Box::new(setup.rax_variable.clone()),
            }),
            rhs: Box::new(Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(1),
                    size: ByteSize::new(1),
                    arg: Box::new(setup.rax_variable.clone()),
                }),
                rhs: Box::new(Expression::Const(Bitvector::zero(ByteSize::new(1).into()))),
            }),
        }),
        rhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(0),
            size: ByteSize::new(1),
            arg: Box::new(setup.rax_variable.clone()),
        }),
    };

    expr.piece_two_expressions_together(&setup.rax_register, &setup.eax_register);
    higher_byte_exp
        .piece_two_expressions_together(&setup.rax_register, &setup.higher_byte_register);
    assert_eq!(expr, expected_expr);
    assert_eq!(higher_byte_exp, expected_higher_byte_expr);

    let higher_half_rax = RegisterProperties {
        register: "upper_RAX_half".to_string(),
        base_register: "RAX".to_string(),
        lsb: ByteSize::new(4),
        size: ByteSize::new(4),
    };
    let mut expression = Expression::Const(Bitvector::from_u32(42));

    let expected_output = Expression::BinOp {
        op: BinOpType::Piece,
        lhs: Box::new(expression.clone()),
        rhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize(0),
            size: ByteSize::new(4),
            arg: Box::new(setup.rax_variable.clone()),
        }),
    };
    expression.piece_two_expressions_together(&setup.rax_register, &higher_half_rax);
    assert_eq!(expression, expected_output);
}

#[test]
fn piecing_extending_or_none() {
    let setup = Setup::new();
    let zero_extend: Option<Tid> = Some(Tid::new("zero_tid"));
    let output_size: Option<ByteSize> = Some(ByteSize::new(8));
    let mut expr = setup.int_sub_expr.clone();
    let expected_expr_with_zero_extend = Expression::Cast {
        op: CastOpType::IntZExt,
        size: ByteSize::new(8),
        arg: Box::new(setup.int_sub_expr.clone()),
    };
    // Test assumes that the next instruction is a zero extension of the current output
    expr.piece_zero_extend_or_none(
        zero_extend,
        Some(&&setup.rax_register),
        output_size,
        Some(&setup.eax_register),
    );
    assert_eq!(expr, expected_expr_with_zero_extend);

    expr = setup.int_sub_expr.clone();
    // Test assumes there is no output (i.e. virtual register output)
    expr.piece_zero_extend_or_none(None, None, None, None);
    assert_eq!(expr, setup.int_sub_expr);

    expr = setup.int_sub_subpiece_expr.clone();

    let expected_expr_with_piecing = Expression::BinOp {
        op: BinOpType::Piece,
        lhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(4),
            size: ByteSize::new(4),
            arg: Box::new(setup.rax_variable.clone()),
        }),
        rhs: Box::new(setup.int_sub_subpiece_expr.clone()),
    };
    // Test assume output is a base register and the input needs to be pieced together
    expr.piece_zero_extend_or_none(
        None,
        Some(&&setup.rax_register),
        output_size,
        Some(&setup.eax_register),
    );
    assert_eq!(expr, expected_expr_with_piecing);
}

#[test]
fn sub_register_check() {
    let setup = Setup::new();
    let mut expr = setup.int_sub_expr.clone();
    let mut register_map = setup.register_map.clone();
    register_map.insert(&setup.eax_name, &setup.eax_register);
    register_map.insert(&setup.rax_name, &setup.rax_register);
    register_map.insert(&setup.ecx_name, &setup.ecx_register);
    register_map.insert(&setup.rcx_name, &setup.rcx_register);

    expr.replace_input_sub_register(&register_map);
    assert_eq!(expr, setup.int_sub_subpiece_expr);
}

#[test]
fn processing_sub_registers() {
    let setup = Setup::new();

    let mut register_map = setup.register_map.clone();
    register_map.insert(&setup.eax_name, &setup.eax_register);
    register_map.insert(&setup.rax_name, &setup.rax_register);
    register_map.insert(&setup.ecx_name, &setup.ecx_register);
    register_map.insert(&setup.rcx_name, &setup.rcx_register);

    // Test Case: Subregister output
    let out_sub = Variable {
        name: setup.eax_name.clone(),
        size: ByteSize::new(4),
        is_temp: false,
    };
    // Test Case: Baseregister output
    let mut out_base = Variable {
        name: setup.rax_name.clone(),
        size: ByteSize::new(8),
        is_temp: false,
    };
    // Test Case: Virtual register output
    let mut out_virtual = Variable {
        name: String::from("$u560"),
        size: ByteSize::new(8),
        is_temp: true,
    };
    // Test Case: Following instruction is a zero extend
    let mut def_term_ext = Term {
        tid: Tid::new("int_zext"),
        term: Def::Assign {
            var: out_base.clone(),
            value: Expression::Cast {
                op: CastOpType::IntZExt,
                size: ByteSize::new(8),
                arg: Box::new(setup.eax_variable.clone()),
            },
        },
    };
    // Test Case: Following instruction is not a zero extend
    let mut def_term = Term {
        tid: Tid::new("int_sext"),
        term: Def::Assign {
            var: out_base.clone(),
            value: Expression::Cast {
                op: CastOpType::IntSExt,
                size: ByteSize::new(8),
                arg: Box::new(setup.eax_variable.clone()),
            },
        },
    };

    // 1. Test: peeked is a zero extension and output is a sub register
    // Expects: Sub register casted to base and zero extension detected
    let def_term_ext_pointer = &mut def_term_ext;
    let mut peeked = Some(&def_term_ext_pointer);
    let mut sub_reg_output = out_sub.clone();
    let mut output = Some(&mut sub_reg_output);
    let mut expr = setup.int_sub_expr.clone();
    let mut expected_expr = Expression::Cast {
        op: CastOpType::IntZExt,
        size: ByteSize::new(8),
        arg: Box::new(setup.int_sub_subpiece_expr.clone()),
    };

    expr.cast_sub_registers_to_base_register_subpieces(output, &register_map, peeked);
    assert_eq!(expr, expected_expr);

    // 2. Test: peeked is not a zero extend and output is a sub register
    // Expects: Piece input together to get the base register size
    let def_term_pointer = &mut def_term;
    peeked = Some(&def_term_pointer);
    expr = setup.int_sub_expr.clone();
    expected_expr = Expression::BinOp {
        op: BinOpType::Piece,
        lhs: Box::new(Expression::Subpiece {
            low_byte: ByteSize::new(4),
            size: ByteSize::new(4),
            arg: Box::new(setup.rax_variable.clone()),
        }),
        rhs: Box::new(setup.int_sub_subpiece_expr.clone()),
    };
    let mut sub_reg_output = out_sub.clone();
    output = Some(&mut sub_reg_output);
    expr.cast_sub_registers_to_base_register_subpieces(output, &register_map, peeked);
    assert_eq!(expr, expected_expr);

    // 3. Test: peek is neglectable and output is a base register
    let def_term_pointer = &mut def_term;
    peeked = Some(&def_term_pointer);
    expr = setup.int_sub_expr.clone();
    output = Some(&mut out_base);
    expr.cast_sub_registers_to_base_register_subpieces(output, &register_map, peeked);
    assert_eq!(expr, setup.int_sub_subpiece_expr);

    // 4. Test: peek is neglectable and output is a virtual register
    let def_term_pointer = &mut def_term;
    peeked = Some(&def_term_pointer);
    expr = setup.int_sub_expr.clone();
    output = Some(&mut out_virtual);
    expr.cast_sub_registers_to_base_register_subpieces(output, &register_map, peeked);
    assert_eq!(expr, setup.int_sub_subpiece_expr);
}
