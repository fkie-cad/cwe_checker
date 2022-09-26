use crate::intermediate_representation::CastOpType;

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
                lhs: Box::new(Expression::Var(Variable::mock("EAX", 4))),
                rhs: Box::new(Expression::Var(Variable::mock("ECX", 4))),
            },
            int_sub_subpiece_expr: Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(Expression::Var(Variable::mock("RAX", 8))),
                }),
                rhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(Expression::Var(Variable::mock("RCX", 8))),
                }),
            },
            eax_variable: Expression::Var(Variable::mock("EAX", 4)),
            rax_variable: Expression::Var(Variable::mock("RAX", 8)),
            rcx_variable: Expression::Var(Variable::mock("RCX", 8)),
        }
    }
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

    expr = create_subpiece_from_sub_register(setup.rax_name.clone(), size, lsb, &register_map);
    assert_eq!(expr, expected_expr);
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

    expr = replace_input_subregister(expr, &register_map);
    assert_eq!(expr, setup.int_sub_subpiece_expr);
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

    expr = piece_base_register_assignment_expression_together(
        &expr,
        &setup.rax_register,
        &setup.eax_register,
    );
    higher_byte_exp = piece_base_register_assignment_expression_together(
        &higher_byte_exp,
        &setup.rax_register,
        &setup.higher_byte_register,
    );
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
            low_byte: ByteSize::new(0),
            size: ByteSize::new(4),
            arg: Box::new(setup.rax_variable.clone()),
        }),
    };
    expression = piece_base_register_assignment_expression_together(
        &expression,
        &setup.rax_register,
        &higher_half_rax,
    );
    assert_eq!(expression, expected_output);
}

#[test]
fn piecing_or_zero_extending() {
    let setup = Setup::new();
    let mut register_map = setup.register_map.clone();
    register_map.insert(&setup.eax_name, &setup.eax_register);
    register_map.insert(&setup.rax_name, &setup.rax_register);
    register_map.insert(&setup.ecx_name, &setup.ecx_register);
    register_map.insert(&setup.rcx_name, &setup.rcx_register);


    let eax_assign_def = Term {
        tid: Tid::new("eax_assign"),
        term: Def::Assign {
            var: Variable::mock("EAX", 4),
            value: Expression::Const(Bitvector::from_i32(0).into()),
        },
    };
    let zero_extension_def = Term {
        tid: Tid::new("zero_extension"),
        term: Def::Assign {
            var: Variable::mock("RAX", 8),
            value: Expression::Cast {
                op: CastOpType::IntZExt,
                size: ByteSize::new(8),
                arg: Box::new(setup.eax_variable.clone()),
            },
        },
    };
    // Test when the next instruction is a zero extension.
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![eax_assign_def, zero_extension_def],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        }
    };

    replace_subregister_in_block(&mut block, &register_map);

    for def in block.term.defs.iter() {
        println!("{}: {}", def.tid, def.term);
    }
    todo!(); // Check correct output

    todo!(); // Test case with wrong target register for the zero extension.

    todo!(); // Test case with target register of zero extension also being a subregister.

    todo!(); // Test case with a load instruction as first instruction.
}


/*
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

*/