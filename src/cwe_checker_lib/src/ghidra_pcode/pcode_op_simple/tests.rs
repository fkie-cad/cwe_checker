use super::*;
use crate::ghidra_pcode::tests::*;
use crate::ghidra_pcode::ExpressionType::*;
use crate::ghidra_pcode::PcodeOperation::ExpressionType;
use crate::ghidra_pcode::PcodeOperation::JmpType;
use crate::pcode::JmpType::*;
use crate::variable;
use crate::{def, expr};

/// Simplified construction of pcode operation with `pcode_index: 1` and
/// pcode_mnemonic: ExpressionType(INT_ADD).
fn mock_pcode_op_add(
    input0: VarnodeSimple,
    input1: Option<VarnodeSimple>,
    output: Option<VarnodeSimple>,
) -> PcodeOpSimple {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(INT_ADD),
        input0,
        input1,
        input2: None,
        output,
    }
}

impl PcodeOpSimple {
    fn with_mnemonic(&self, mnemonic: PcodeOperation) -> PcodeOpSimple {
        PcodeOpSimple {
            pcode_index: self.pcode_index,
            pcode_mnemonic: mnemonic,
            input0: self.input0.clone(),
            input1: self.input1.clone(),
            input2: self.input2.clone(),
            output: self.output.clone(),
        }
    }

    fn with_varnodes(
        mut self,
        input0: VarnodeSimple,
        input1: Option<VarnodeSimple>,
        input2: Option<VarnodeSimple>,
        output: Option<VarnodeSimple>,
    ) -> PcodeOpSimple {
        self.input0 = input0;
        self.input1 = input1;
        self.input2 = input2;
        self.output = output;
        self
    }
}

#[test]
fn test_pcode_op_has_implicit_load() {
    let ram_varnode = mock_varnode("ram", "0x42", 8);
    let varnode = mock_varnode("register", "RAX", 8);
    let pcode_op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(STORE),
        input0: ram_varnode.clone(),
        input1: None,
        input2: None,
        output: None,
    };
    assert_eq!(pcode_op.has_implicit_load(), true);
    assert_eq!(
        pcode_op
            .clone()
            .with_varnodes(varnode.clone(), Some(ram_varnode.clone()), None, None)
            .has_implicit_load(),
        true
    );
    assert_eq!(
        pcode_op
            .clone()
            .with_varnodes(varnode.clone(), None, Some(ram_varnode.clone()), None)
            .has_implicit_load(),
        true
    );
    assert_eq!(
        pcode_op
            .clone()
            .with_varnodes(varnode.clone(), None, None, None)
            .has_implicit_load(),
        false
    );
    assert_eq!(
        pcode_op
            .clone()
            .with_varnodes(varnode.clone(), Some(varnode.clone()), None, None)
            .has_implicit_load(),
        false
    );
    assert_eq!(
        pcode_op
            .with_varnodes(varnode.clone(), None, Some(varnode.clone()), None)
            .has_implicit_load(),
        false
    );
}

#[test]
fn test_pcode_op_has_implicit_store() {
    let ram_varnode = mock_varnode("ram", "0x42", 8);
    let varnode = mock_varnode("register", "RAX", 8);
    assert_eq!(
        mock_pcode_op_add(varnode.clone(), None, Some(ram_varnode)).has_implicit_store(),
        true
    );
    assert_eq!(
        mock_pcode_op_add(varnode.clone(), None, Some(varnode)).has_implicit_store(),
        false
    );
}

#[test]
fn test_implicit_load_translation() {
    let ram_varnode = mock_varnode("ram", "0x42", 8);
    let varnode = mock_varnode("register", "RAX", 8);
    let load0_target = Variable {
        name: "$load_temp0".into(),
        size: 8.into(),
        is_temp: true,
    };
    let expected_load0 = Term {
        tid: Tid {
            id: "".into(),
            address: "0x1234".into(),
        },
        term: Def::Load {
            var: load0_target.clone(),
            address: expr!("0x42:8"),
        },
    };

    let mut load1_target = load0_target.clone();
    load1_target.name = "$load_temp1".into();
    let mut expected_load1 = expected_load0.clone();
    expected_load1.term = Def::Load {
        var: load1_target.clone(),
        address: expr!("0x42:8"),
    };

    let mut load2_target = load0_target.clone();
    load2_target.name = "$load_temp2".into();
    let mut expected_load2 = expected_load0.clone();
    expected_load2.term = Def::Load {
        var: load2_target.clone(),
        address: expr!("0x42:8"),
    };
    // No implicit load
    assert_eq!(
        mock_pcode_op_add(varnode.clone(), None, None).create_implicit_loads(&"0x1234".to_string()),
        vec![]
    );
    // input0 is implicit load
    assert_eq!(
        mock_pcode_op_add(ram_varnode.clone(), None, None)
            .create_implicit_loads(&"0x1234".to_string()),
        vec![expected_load0
            .clone()
            .with_tid_id("instr_0x1234_1_load0".into())]
    );
    // input1 is implicit load
    assert_eq!(
        mock_pcode_op_add(varnode.clone(), Some(ram_varnode.clone()), None)
            .create_implicit_loads(&"0x1234".to_string()),
        vec![expected_load1
            .clone()
            .with_tid_id("instr_0x1234_1_load1".into())]
    );
    // input2 is implicit load
    assert_eq!(
        PcodeOpSimple {
            pcode_index: 1,
            pcode_mnemonic: ExpressionType(STORE),
            input0: varnode.clone(),
            input1: None,
            input2: Some(ram_varnode.clone()),
            output: None
        }
        .create_implicit_loads(&"0x1234".to_string()),
        vec![expected_load2
            .clone()
            .with_tid_id("instr_0x1234_1_load2".into())]
    );
    // input0, input1 and input2 are implicit loads
    assert_eq!(
        PcodeOpSimple {
            pcode_index: 1,
            pcode_mnemonic: ExpressionType(INT_ZEXT),
            input0: ram_varnode.clone(),
            input1: Some(ram_varnode.clone()),
            input2: Some(ram_varnode.clone()),
            output: None
        }
        .create_implicit_loads(&"0x1234".to_string()),
        vec![
            expected_load0.with_tid_id("instr_0x1234_1_load0".into()),
            expected_load1.with_tid_id("instr_0x1234_1_load1".into()),
            expected_load2.with_tid_id("instr_0x1234_1_load2".into()),
        ]
    );
}

#[test]
fn test_create_load() {
    let load_target = mock_varnode("register", "RAX", 8);
    let source = mock_varnode("const", "0x0012345", 8);
    let pcode_op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: source.clone(),
        input1: Some(source),
        input2: None,
        output: Some(load_target),
    };

    assert_eq!(
        pcode_op.create_load(&"0xFFFFFF".to_string()),
        Term {
            tid: Tid {
                id: "instr_0xFFFFFF_1".into(),
                address: "0xFFFFFF".into()
            },
            term: def!["RAX:8 := Load from 0x0012345:8"].term
        }
    );
}

#[test]
#[should_panic]
fn test_create_load_not_load() {
    mock_pcode_op_add(mock_varnode("space", "id", 8), None, None).create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_no_output() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: mock_varnode("space", "id", 8),
        input1: Some(mock_varnode("const", "0x200", 8)),
        input2: None,
        output: None,
    }
    .create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_no_source() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: mock_varnode("space", "id", 8),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_target_not_var() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: mock_varnode("space", "id", 8),
        input1: Some(mock_varnode("const", "0x200", 8)),
        input2: None,
        output: Some(mock_varnode("const", "0x4321", 8)),
    }
    .create_load(&"0x123".to_string());
}

#[test]
fn test_create_store() {
    let data = mock_varnode("const", "0x0042", 8);
    let target = mock_varnode("register", "RAX", 8);
    let pcode_op = PcodeOpSimple {
        pcode_index: 5,
        pcode_mnemonic: ExpressionType(STORE),
        input0: mock_varnode("space", "id", 8),
        input1: Some(target),
        input2: Some(data),
        output: None,
    };
    assert_eq!(
        pcode_op.create_store(&"0x00ABCDEF".to_string()),
        Term {
            tid: Tid {
                id: "instr_0x00ABCDEF_5".into(),
                address: "0x00ABCDEF".into()
            },
            term: def!["Store at RAX:8 := 0x0042:8"].term
        }
    )
}

#[test]
#[should_panic]
fn test_create_store_not_store() {
    mock_pcode_op_add(mock_varnode("space", "id", 8), None, None)
        .create_store(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_store_no_target() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(STORE),
        input0: mock_varnode("space", "id", 8),
        input1: None,
        input2: Some(mock_varnode("const", "0x4321", 8)),
        output: None,
    }
    .create_store(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_store_from_ram() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(STORE),
        input0: mock_varnode("space", "id", 8),
        input1: Some(mock_varnode("const", "0x4321", 8)),
        input2: Some(mock_varnode("ram", "0xFFFF01", 8)),
        output: None,
    }
    .create_store(&"0x123".to_string());
}

#[test]
fn test_create_subpice() {
    let op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(SUBPIECE),
        input0: mock_varnode("const", "0xAABBCCDD", 8),
        input1: Some(mock_varnode("const", "0x3", 1)),
        input2: None,
        output: Some(mock_varnode("register", "EAX", 4)),
    };
    let expected_expr = Expression::Subpiece {
        low_byte: 3.into(),
        size: 4.into(),
        arg: Box::new(Expression::Const(Bitvector::from_u64(0xAABBCCDD))),
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1234_1".to_string(),
            address: "0x1234".to_string(),
        },
        term: Def::Assign {
            var: variable!("EAX:4"),
            value: expected_expr,
        },
    };
    assert_eq!(op.create_subpice(&"0x1234".to_string()), expected);
}

#[test]
#[should_panic]
fn test_create_subpice_with_non_constant() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(SUBPIECE),
        input0: mock_varnode("const", "0xABCDEF", 8),
        input1: Some(mock_varnode("register", "RAX", 8)),
        input2: None,
        output: Some(mock_varnode("register", "EAX", 4)),
    }
    .create_subpice(&"0x1234".to_string());
}

#[test]
fn test_create_unop() {
    let op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(INT_NEGATE),
        input0: mock_varnode("register", "RAX", 8),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    };
    let mut expected = def!["instr_0x1234_1: RAX:8 = -(RAX:8)"];
    expected.tid.address = "0x1234".to_string();
    assert_eq!(op.create_unop(&"0x1234".to_string()), expected);

    expected.term = def!["RAX:8 = ¬(RAX:8)"].term;
    assert_eq!(
        op.with_mnemonic(ExpressionType(BOOL_NEGATE))
            .create_unop(&"0x1234".to_string()),
        expected
    )
}

#[test]
#[should_panic]
fn test_create_unop_not_expression_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: JmpType(CALL),
        input0: mock_varnode("register", "RAX", 8),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_unop(&"0xFFFF".to_string());
}

#[test]
#[should_panic]
fn test_create_unop_not_unop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(INT_AND),
        input0: mock_varnode("register", "RAX", 8),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_unop(&"0xFFFF".to_string());
}

#[test]
fn test_create_biop() {
    let op = mock_pcode_op_add(
        mock_varnode("register", "RAX", 8),
        Some(mock_varnode("const", "0xCAFE", 4)),
        Some(mock_varnode("register", "RAX", 8)),
    );

    let expected = Term {
        tid: Tid {
            id: "instr_0x1234_1".into(),
            address: "0x1234".into(),
        },
        term: def!["RAX:8 = RAX:8 + 0xCAFE:4"].term,
    };
    assert_eq!(op.create_biop(&"0x1234".to_string()), expected)
}

#[test]
#[should_panic]
fn test_create_biop_not_expression_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: JmpType(CALL),
        input0: mock_varnode("register", "RAX", 8),
        input1: Some(mock_varnode("const", "0xCAFE", 4)),
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_biop(&"0x1234".to_string());
}

#[test]
#[should_panic]
fn test_create_biop_not_biop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(COPY),
        input0: mock_varnode("register", "RAX", 8),
        input1: Some(mock_varnode("const", "0xCAFE", 4)),
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_biop(&"0x1234".to_string());
}

#[test]
fn test_create_cast_op() {
    let op = PcodeOpSimple {
        pcode_index: 9,
        pcode_mnemonic: PcodeOperation::ExpressionType(INT_ZEXT),
        input0: mock_varnode("const", "0x1", 1),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "RDI", 8)),
    };
    let expected_expr = Expression::Cast {
        op: CastOpType::IntZExt,
        size: 8.into(),
        arg: Box::new(expr!("0x1:1")),
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x4321_9".into(),
            address: "0x4321".into(),
        },
        term: Def::Assign {
            var: variable!("RDI:8"),
            value: expected_expr,
        },
    };
    assert_eq!(op.create_castop(&"0x4321".to_string()), expected);
}

#[test]
#[should_panic]
fn test_create_castop_not_expression_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: JmpType(CALL),
        input0: mock_varnode("register", "RAX", 8),
        input1: Some(mock_varnode("const", "0xCAFE", 4)),
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_castop(&"0x1234".to_string());
}

#[test]
#[should_panic]
fn test_create_castop_not_castop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(COPY),
        input0: mock_varnode("register", "RAX", 8),
        input1: Some(mock_varnode("const", "0xCAFE", 4)),
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_castop(&"0x1234".to_string());
}

#[test]
fn test_create_assign() {
    let op = PcodeOpSimple {
        pcode_index: 2,
        pcode_mnemonic: ExpressionType(COPY),
        input0: mock_varnode("const", "0x42", 1),
        input1: None,
        input2: None,
        output: Some(mock_varnode("register", "ZF", 1)),
    };
    let expected = Term {
        tid: Tid {
            id: "instr_0x1111_2".to_string(),
            address: "0x1111".to_string(),
        },
        term: def!["ZF:1 = 0x42:1"].term,
    };
    assert_eq!(expected, op.create_assign(&"0x1111".to_string()))
}

#[test]
#[should_panic]
fn test_create_assign_not_copy_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(BOOL_AND),
        input0: mock_varnode("register", "RAX", 8),
        input1: Some(mock_varnode("const", "0xCAFE", 4)),
        input2: None,
        output: Some(mock_varnode("register", "RAX", 8)),
    }
    .create_assign(&"0x1234".to_string());
}

#[test]
fn test_wrap_in_assign_or_store() {
    let mut op = mock_pcode_op_add(
        mock_varnode("register", "EAX", 4),
        Some(mock_varnode("const", "0xCAFE", 4)),
        Some(mock_varnode("register", "EAX", 4)),
    );

    let expr = expr!("EAX:4 + 0xCAFE:4");
    // test Assign
    let mut expected = Term {
        tid: Tid {
            id: "instr_0xAFFE_1".to_string(),
            address: "0xAFFE".to_string(),
        },
        term: def!["EAX:4 = EAX:4 + 0xCAFE:4"].term,
    };
    assert_eq!(
        expected,
        op.wrap_in_assign_or_store(&"0xAFFE".to_string(), expr.clone())
    );

    // test Store
    op.output = Some(mock_varnode("ram", "0x1234", 4));
    expected.term = def!["Store at 0x1234:4 := EAX:4 + 0xCAFE:4"].term;
    assert_eq!(
        op.wrap_in_assign_or_store(&"0xAFFE".to_string(), expr),
        expected
    )
}

#[test]
#[should_panic]
fn test_wrap_in_assign_or_store_output_not_variable_nor_implicit_store() {
    mock_pcode_op_add(
        mock_varnode("register", "EAX", 4),
        Some(mock_varnode("const", "0xCAFE", 4)),
        Some(mock_varnode("const", "0xFFFF", 4)),
    )
    .wrap_in_assign_or_store(&"0x1234".to_string(), expr!("0x1111:4"));
}
