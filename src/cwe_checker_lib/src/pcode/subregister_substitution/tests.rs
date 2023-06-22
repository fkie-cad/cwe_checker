use super::*;
use crate::{def, expr, intermediate_representation::*, variable};

struct Setup<'a> {
    register_map: HashMap<&'a String, &'a RegisterProperties>,
    eax_name: String,
    rax_name: String,
    ecx_name: String,
    rcx_name: String,
    ah_name: String,
    eax_register: RegisterProperties,
    rax_register: RegisterProperties,
    ecx_register: RegisterProperties,
    rcx_register: RegisterProperties,
    ah_register: RegisterProperties,
    int_sub_expr: Expression,
    int_sub_subpiece_expr: Expression,
    eax_variable: Expression,
    rax_variable: Expression,
}

impl<'a> Setup<'a> {
    fn new() -> Self {
        Self {
            register_map: HashMap::new(),
            eax_name: String::from("EAX"),
            rax_name: String::from("RAX"),
            ecx_name: String::from("ECX"),
            rcx_name: String::from("RCX"),
            ah_name: String::from("AH"),
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
            ah_register: RegisterProperties {
                register: String::from("AH"),
                base_register: String::from("RAX"),
                lsb: ByteSize::new(1),
                size: ByteSize::new(1),
            },
            int_sub_expr: Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(expr!("EAX:4")),
                rhs: Box::new(expr!("ECX:4")),
            },
            int_sub_subpiece_expr: Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(expr!("RAX:8")),
                }),
                rhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(4),
                    arg: Box::new(expr!("RCX:8")),
                }),
            },
            eax_variable: expr!("EAX:4"),
            rax_variable: expr!("RAX:8"),
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

    let expected_expr = Expression::Subpiece {
        low_byte: ByteSize::new(0),
        size: ByteSize::new(4),
        arg: Box::new(setup.rax_variable.clone()),
    };

    let expr = create_subpiece_from_sub_register(setup.rax_name.clone(), size, lsb, &register_map);
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
        &setup.ah_register,
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

/// Check whether the format strings when printing the defs of the given block are as expected.
/// Return false if the number of elements does not match or at least one format string differs from the expected result.
fn check_defs_of_block(block: &Term<Blk>, expected: Vec<&str>) -> bool {
    if block.term.defs.len() != expected.len() {
        println!(
            "lengths do not match: {} != {}",
            block.term.defs.len(),
            expected.len()
        );
        return false;
    }
    for (def, expected_def) in block.term.defs.iter().zip(expected.iter()) {
        let format_string = format!("{}: {}", def.tid, def.term);
        if &format_string != expected_def {
            println!("Def does not match:");
            println!("   given: {}", format_string);
            println!("expected: {}", expected_def);
            return false;
        }
    }
    true
}

#[test]
fn piecing_or_zero_extending() {
    let setup = Setup::new();
    let mut register_map = setup.register_map.clone();
    register_map.insert(&setup.eax_name, &setup.eax_register);
    register_map.insert(&setup.rax_name, &setup.rax_register);
    register_map.insert(&setup.ecx_name, &setup.ecx_register);
    register_map.insert(&setup.rcx_name, &setup.rcx_register);
    register_map.insert(&setup.ah_name, &setup.ah_register);

    let eax_assign = def!["eax_assign: EAX:4 = 0:4"];
    let load_to_eax = def!["load_to_eax: EAX:4 := Load from 0:8"];
    let ah_assign = def!["ah_assign: AH:1 = 0:1"];
    let zext_eax_to_rax = Term {
        tid: Tid::new("zext_eax_to_rax"),
        term: Def::Assign {
            var: variable!("RAX:8"),
            value: Expression::cast(setup.eax_variable.clone(), CastOpType::IntZExt),
        },
    };
    let zext_ah_to_eax = Term {
        tid: Tid::new("zext_ah_to_eax"),
        term: Def::Assign {
            var: variable!("EAX:4"),
            value: Expression::cast(expr!("AH:1"), CastOpType::IntZExt),
        },
    };
    let zext_ah_to_rax = Term {
        tid: Tid::new("zext_ah_to_rax"),
        term: Def::Assign {
            var: variable!("RAX:8"),
            value: Expression::cast(expr!("AH:1"), CastOpType::IntZExt),
        },
    };
    let zext_eax_to_rcx = Term {
        tid: Tid::new("zext_eax_to_rcx"),
        term: Def::Assign {
            var: variable!("RCX:8"),
            value: Expression::cast(setup.eax_variable.clone(), CastOpType::IntZExt),
        },
    };

    // Test when the next instruction is a zero extension to the base register.
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![eax_assign.clone(), zext_eax_to_rax.clone()],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec!["zext_eax_to_rax: RAX:8 = IntZExt(0x0:4)"]
    ));

    // Test whether zero extension to base register is still recognized
    // even if the sub-register starts not at byte zero of the base register.
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![ah_assign.clone(), zext_ah_to_rax],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec!["zext_ah_to_rax: RAX:8 = IntZExt(0x0:1)"]
    ));

    // Test when the next register is a zero extension to a different register.
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![eax_assign, zext_eax_to_rcx.clone()],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec![
            "eax_assign: RAX:8 = ((RAX:8)[4-7] Piece 0x0:4)",
            "zext_eax_to_rcx: RCX:8 = IntZExt((RAX:8)[0-3])"
        ]
    ));

    // Test when target of zero extension is also a sub-register
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![ah_assign.clone(), zext_ah_to_eax],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec![
            "ah_assign: RAX:8 = (((RAX:8)[2-7] Piece 0x0:1) Piece (RAX:8)[0-0])",
            "zext_ah_to_eax: RAX:8 = ((RAX:8)[4-7] Piece IntZExt((RAX:8)[1-1]))",
        ]
    ));

    // Test when loading to a sub-register with a zero extension to the base register as next instruction
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![load_to_eax.clone(), zext_eax_to_rax],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec![
            "load_to_eax: loaded_value:4(temp) := Load from 0x0:8",
            "zext_eax_to_rax: RAX:8 = IntZExt(loaded_value:4(temp))",
        ]
    ));

    // Test when loading to a sub-register without a zero extension to the base register as next instruction
    let mut block = Term {
        tid: Tid::new("block"),
        term: Blk {
            defs: vec![load_to_eax, zext_eax_to_rcx],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };
    replace_subregister_in_block(&mut block, &register_map);
    assert!(check_defs_of_block(
        &block,
        vec![
            "load_to_eax: loaded_value:4(temp) := Load from 0x0:8",
            "load_to_eax_cast_to_base: RAX:8 = ((RAX:8)[4-7] Piece loaded_value:4(temp))",
            "zext_eax_to_rcx: RCX:8 = IntZExt((RAX:8)[0-3])"
        ]
    ));
}
