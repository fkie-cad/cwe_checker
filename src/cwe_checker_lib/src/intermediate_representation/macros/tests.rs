use crate::intermediate_representation::*;

#[test]
fn test_var() {
    assert_eq!(
        variable!("RAX:8"),
        Variable {
            name: "RAX".to_string(),
            size: ByteSize(8),
            is_temp: false
        }
    );
}
#[test]
#[should_panic]
fn var_empty_panics() {
    variable!("");
}
#[test]
#[should_panic]
fn var_no_colon_panics() {
    variable!("RAX8");
}

#[test]
#[should_panic]
fn var_no_size_panics() {
    variable!("RAX:");
}

#[test]
fn test_bitvec() {
    assert_eq!(bitvec!("0x42:1"), Bitvector::from_u8(0x42));
    assert_eq!(bitvec!("0xFF:2"), Bitvector::from_u16(0xFF));
    assert_eq!(bitvec!("0xAAFF:1"), Bitvector::from_u8(0xFF));
    assert_eq!(bitvec!("0x-01:1"), Bitvector::from_i8(-1));
    assert_eq!(bitvec!("123:4"), Bitvector::from_u32(123));
    assert_eq!(bitvec!("-42:8"), Bitvector::from_i64(-42));
}

#[test]
fn test_expr_var() {
    assert_eq!(
        expr!("RAX:8"),
        Expression::Var(Variable {
            name: "RAX".into(),
            size: ByteSize(8),
            is_temp: false
        })
    );
}
#[test]
fn test_expr_const() {
    assert_eq!(
        expr!("0x42:8"),
        Expression::Const(Bitvector::from_u64(0x42))
    );
    assert_eq!(
        expr!("0xFFFF:1"),
        Expression::Const(Bitvector::from_u8(255))
    );
    assert_eq!(expr!("42:4"), Expression::Const(Bitvector::from_u32(42)));
}
#[test]
fn test_expr_plus() {
    assert_eq!(
        expr!("RAX:8 + 0x42:8"),
        Expression::BinOp {
            op: BinOpType::IntAdd,
            lhs: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize(8),
                is_temp: false
            })),
            rhs: Box::new(Expression::Const(Bitvector::from_u64(0x42)))
        }
    );
}
#[test]
fn test_expr_minus() {
    assert_eq!(
        expr!("RAX:8 - 0x42:8"),
        Expression::BinOp {
            op: BinOpType::IntSub,
            lhs: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize(8),
                is_temp: false
            })),
            rhs: Box::new(Expression::Const(Bitvector::from_u64(0x42)))
        }
    );
}
#[test]
fn test_expr_int_negate() {
    assert_eq!(
        expr!("-(RAX:8)"),
        Expression::UnOp {
            op: UnOpType::IntNegate,
            arg: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize(8),
                is_temp: false
            }))
        }
    );
}
#[test]
fn test_expr_bool_negate() {
    assert_eq!(
        expr!("¬(RAX:8)"),
        Expression::UnOp {
            op: UnOpType::BoolNegate,
            arg: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize(8),
                is_temp: false
            }))
        }
    );
}
#[test]
fn test_def_tid() {
    let defs = defs![
        "RDI:8 = RAX:8 + RBP:8",
        "A: RAX:8 = 0x42:1",
        "RDX:8 = RAX:8 + RBP:8"
    ];
    assert_eq!(
        defs.into_iter()
            .map(|x| x.tid.to_string())
            .collect::<Vec<String>>(),
        ["tid_0", "A", "tid_2"]
    )
}
#[test]
fn test_defs_assign() {
    assert_eq!(
        defs!["tid_0: RAX:8 = 0x42:1", "tid_1: RDI:8 = RAX:8 + RBP:8"],
        vec![
            Term {
                tid: Tid::new("tid_0"),
                term: Def::Assign {
                    var: Variable {
                        name: "RAX".into(),
                        size: ByteSize(8),
                        is_temp: false
                    },
                    value: Expression::Const(Bitvector::from_i8(0x42))
                }
            },
            Term {
                tid: Tid::new("tid_1"),
                term: Def::Assign {
                    var: Variable {
                        name: "RDI".into(),
                        size: ByteSize(8),
                        is_temp: false
                    },
                    value: Expression::BinOp {
                        op: BinOpType::IntAdd,
                        lhs: Box::new(Expression::Var(Variable {
                            name: "RAX".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })),
                        rhs: Box::new(Expression::Var(Variable {
                            name: "RBP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        }))
                    }
                }
            }
        ]
    );
}

#[test]
fn test_defs_store() {
    assert_eq!(
        defs!["tid: Store at RSP:8 - 0x8:1 := 0x42:1"],
        vec![Term {
            tid: Tid::new("tid"),
            term: Def::Store {
                address: Expression::BinOp {
                    op: BinOpType::IntSub,
                    lhs: Box::new(Expression::Var(Variable {
                        name: "RSP".into(),
                        size: ByteSize(8),
                        is_temp: false
                    })),
                    rhs: Box::new(Expression::Const(Bitvector::from_u8(0x8)))
                },
                value: Expression::Const(Bitvector::from_u8(0x42))
            }
        }]
    )
}

#[test]
fn test_defs_load() {
    assert_eq!(
        defs!["tid_a: RAX:8 := Load from 0xFF00:4 + 0x08:4"],
        vec![Term {
            tid: Tid::new("tid_a"),
            term: Def::Load {
                var: Variable {
                    name: "RAX".into(),
                    size: ByteSize(8),
                    is_temp: false
                },
                address: Expression::BinOp {
                    op: BinOpType::IntAdd,
                    lhs: Box::new(Expression::Const(Bitvector::from_u32(0xFF00))),
                    rhs: Box::new(Expression::Const(Bitvector::from_u32(0x08)))
                }
            }
        }]
    )
}

#[test]
fn test_defs_composition() {
    assert_eq!(
        defs![
            "tid_a: Store at RSP:8 + -(0x8:1) := RAX:8",
            "tid_b: RSP:8 = RSP:8 + ¬(0x8:1)",
            "tid_c: RDI:8 := Load from RSP:8"
        ],
        vec![
            Term {
                tid: Tid::new("tid_a"),
                term: Def::Store {
                    address: Expression::BinOp {
                        op: BinOpType::IntAdd,
                        lhs: Box::new(Expression::Var(Variable {
                            name: "RSP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })),
                        rhs: Box::new(Expression::UnOp {
                            op: UnOpType::IntNegate,
                            arg: Box::new(Expression::Const(Bitvector::from_u8(0x08)))
                        })
                    },
                    value: Expression::Var(Variable {
                        name: "RAX".into(),
                        size: ByteSize(8),
                        is_temp: false
                    })
                }
            },
            Term {
                tid: Tid::new("tid_b"),
                term: Def::Assign {
                    var: Variable {
                        name: "RSP".into(),
                        size: ByteSize(8),
                        is_temp: false
                    },
                    value: Expression::BinOp {
                        op: BinOpType::IntAdd,
                        lhs: Box::new(Expression::Var(Variable {
                            name: "RSP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })),
                        rhs: Box::new(Expression::UnOp {
                            op: UnOpType::BoolNegate,
                            arg: Box::new(Expression::Const(Bitvector::from_u8(0x08)))
                        })
                    }
                }
            },
            Term {
                tid: Tid::new("tid_c"),
                term: Def::Load {
                    var: Variable {
                        name: "RDI".into(),
                        size: ByteSize(8),
                        is_temp: false
                    },
                    address: Expression::Var(Variable {
                        name: "RSP".into(),
                        size: ByteSize(8),
                        is_temp: false
                    })
                }
            }
        ]
    )
}
