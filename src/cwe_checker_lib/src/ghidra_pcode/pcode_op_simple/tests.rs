use super::*;
use crate::ghidra_pcode::ExpressionType::*;
use crate::ghidra_pcode::PcodeOperation::ExpressionType;
use crate::ghidra_pcode::PcodeOperation::JmpType;
use crate::variable;
use crate::{def, expr};

impl PcodeOpSimple {
    /// Mock a P-Code-operation from a string of the form `[output_varnode] mnemonic input0 [input_1] [input2]`.
    /// The `pcode_index` will be set to 0.
    /// Examples:
    /// - `register_RAX_8 INT_ADD register_RBX_8 register_RCX_8`
    /// - `BRANCH const_0x1234_8`
    pub fn mock(pcode_op: &str) -> PcodeOpSimple {
        let mut components = pcode_op.split_whitespace();
        let first_elem = components.next().unwrap();
        let (output, pcode_mnemonic) = if let Ok(mnemonic) =
            serde_json::from_value(serde_json::Value::String(first_elem.into()))
        {
            (None, mnemonic)
        } else {
            (
                Some(VarnodeSimple::mock(first_elem)),
                serde_json::from_value(serde_json::Value::String(
                    components.next().unwrap().to_string(),
                ))
                .unwrap(),
            )
        };
        let input0 = VarnodeSimple::mock(components.next().unwrap());
        let input1 = components
            .next()
            .map(|varnode| VarnodeSimple::mock(varnode));
        let input2 = components
            .next()
            .map(|varnode| VarnodeSimple::mock(varnode));
        assert!(components.next().is_none());
        PcodeOpSimple {
            pcode_index: 0,
            pcode_mnemonic,
            input0,
            input1,
            input2,
            output,
        }
    }
}

#[test]
fn test_pcode_op_simple_mock() {
    assert_eq!(
        PcodeOpSimple::mock("register_RAX_8 INT_ADD register_RBX_8 register_RCX_8"),
        PcodeOpSimple {
            pcode_index: 0,
            pcode_mnemonic: PcodeOperation::ExpressionType(INT_ADD),
            input0: VarnodeSimple::mock("register_RBX_8"),
            input1: Some(VarnodeSimple::mock("register_RCX_8")),
            input2: None,
            output: Some(VarnodeSimple::mock("register_RAX_8"))
        }
    )
}

/// Simplified construction of pcode operation with `pcode_index: 1` and
/// pcode_mnemonic: ExpressionType(INT_ADD).
pub fn mock_pcode_op_add(
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

pub fn mock_pcode_op_branch(pcode_index: u64, input0: VarnodeSimple) -> PcodeOpSimple {
    PcodeOpSimple {
        pcode_index,
        pcode_mnemonic: JmpType(BRANCH),
        input0,
        input1: None,
        input2: None,
        output: None,
    }
}

pub fn mock_pcode_op_cbranch(
    pcode_index: u64,
    input0: VarnodeSimple,
    input1: VarnodeSimple,
) -> PcodeOpSimple {
    PcodeOpSimple {
        pcode_index,
        pcode_mnemonic: JmpType(CBRANCH),
        input0,
        input1: Some(input1),
        input2: None,
        output: None,
    }
}

impl PcodeOpSimple {
    pub fn with_mnemonic(&self, mnemonic: PcodeOperation) -> PcodeOpSimple {
        PcodeOpSimple {
            pcode_index: self.pcode_index,
            pcode_mnemonic: mnemonic,
            input0: self.input0.clone(),
            input1: self.input1.clone(),
            input2: self.input2.clone(),
            output: self.output.clone(),
        }
    }

    pub fn with_index(mut self, index: u64) -> PcodeOpSimple {
        self.pcode_index = index;
        self
    }
}

#[test]
fn test_pcode_op_has_implicit_load() {
    let pcode_op = PcodeOpSimple::mock("register_RAX_8 INT_ADD ram_0x42_8 register_RAX_8");
    assert!(pcode_op.has_implicit_load());
    let pcode_op = PcodeOpSimple::mock("STORE const_0x1b1_8 ram_0x42_8 register_RAX_8");
    assert!(pcode_op.has_implicit_load());
    let pcode_op = PcodeOpSimple::mock("STORE const_0x1b1_8 register_RAX_8 ram_0x42_8");
    assert!(pcode_op.has_implicit_load());
    // No implicit loads
    let pcode_op = PcodeOpSimple::mock("STORE const_0x1b1_8 register_RAX_8 register_RAX_8");
    assert!(!pcode_op.has_implicit_load());
    let pcode_op = PcodeOpSimple::mock("ram_0x42_8 INT_ADD register_RAX_8 register_RAX_8");
    assert!(!pcode_op.has_implicit_load());
}

#[test]
fn test_pcode_op_has_implicit_store() {
    let pcode_op = PcodeOpSimple::mock("ram_0x42_8 INT_ADD register_RAX_8 register_RAX_8");
    assert!(pcode_op.has_implicit_store());
    let pcode_op = PcodeOpSimple::mock("register_RAX_8 INT_ADD ram_0x42_8 register_RAX_8");
    assert!(!pcode_op.has_implicit_store());
}

#[test]
fn test_implicit_load_translation() {
    let ram_varnode = VarnodeSimple::mock("ram_0x42_8");
    let varnode = VarnodeSimple::mock("register_RAX_8");
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
    let load_target = VarnodeSimple::mock("register_RAX_8");
    let source = VarnodeSimple::mock("const_0x0012345_8");
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
            tid: Tid::mock("instr_0xFFFFFF_1"),
            term: def!["RAX:8 := Load from 0x0012345:8"].term
        }
    );
}

#[test]
#[should_panic]
fn test_create_load_not_load() {
    mock_pcode_op_add(VarnodeSimple::mock("space_id_8"), None, None)
        .create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_no_output() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: VarnodeSimple::mock("space_id_8"),
        input1: Some(VarnodeSimple::mock("const_0x200_8")),
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
        input0: VarnodeSimple::mock("space_id_8"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_target_not_var() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(LOAD),
        input0: VarnodeSimple::mock("space_id_8"),
        input1: Some(VarnodeSimple::mock("const_0x200_8")),
        input2: None,
        output: Some(VarnodeSimple::mock("const_0x4321_8")),
    }
    .create_load(&"0x123".to_string());
}

#[test]
fn test_create_store() {
    let data = VarnodeSimple::mock("const_0x0042_8");
    let target = VarnodeSimple::mock("register_RAX_8");
    let pcode_op = PcodeOpSimple {
        pcode_index: 5,
        pcode_mnemonic: ExpressionType(STORE),
        input0: VarnodeSimple::mock("space_id_8"),
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
    mock_pcode_op_add(VarnodeSimple::mock("space_id_8"), None, None)
        .create_store(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_store_no_target() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(STORE),
        input0: VarnodeSimple::mock("space_id_8"),
        input1: None,
        input2: Some(VarnodeSimple::mock("const_0x4321_8")),
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
        input0: VarnodeSimple::mock("space_id_8"),
        input1: Some(VarnodeSimple::mock("const_0x4321_8")),
        input2: Some(VarnodeSimple::mock("ram_0xFFFF01_8")),
        output: None,
    }
    .create_store(&"0x123".to_string());
}

#[test]
fn test_create_subpice() {
    let op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(SUBPIECE),
        input0: VarnodeSimple::mock("const_0xAABBCCDD_8"),
        input1: Some(VarnodeSimple::mock("const_0x3_1")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_EAX_4")),
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
    assert_eq!(op.create_subpiece(&"0x1234".to_string()), expected);
}

#[test]
#[should_panic]
fn test_create_subpiece_with_non_constant() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(SUBPIECE),
        input0: VarnodeSimple::mock("const_0xABCDEF_8"),
        input1: Some(VarnodeSimple::mock("register_RAX_8")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_EAX_4")),
    }
    .create_subpiece(&"0x1234".to_string());
}

#[test]
fn test_create_unop() {
    let op = PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(INT_NEGATE),
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
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
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_unop(&"0xFFFF".to_string());
}

#[test]
#[should_panic]
fn test_create_unop_not_unop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(INT_AND),
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_unop(&"0xFFFF".to_string());
}

#[test]
fn test_create_biop() {
    let op = mock_pcode_op_add(
        VarnodeSimple::mock("register_RAX_8"),
        Some(VarnodeSimple::mock("const_0xCAFE_4")),
        Some(VarnodeSimple::mock("register_RAX_8")),
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
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: Some(VarnodeSimple::mock("const_0xCAFE_4")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_biop(&"0x1234".to_string());
}

#[test]
#[should_panic]
fn test_create_biop_not_biop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(COPY),
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: Some(VarnodeSimple::mock("const_0xCAFE_4")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_biop(&"0x1234".to_string());
}

#[test]
fn test_create_cast_op() {
    let op = PcodeOpSimple {
        pcode_index: 9,
        pcode_mnemonic: PcodeOperation::ExpressionType(INT_ZEXT),
        input0: VarnodeSimple::mock("const_0x1_1"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_RDI_8")),
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
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: Some(VarnodeSimple::mock("const_0xCAFE_4")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_castop(&"0x1234".to_string());
}

#[test]
#[should_panic]
fn test_create_castop_not_castop_type() {
    PcodeOpSimple {
        pcode_index: 1,
        pcode_mnemonic: ExpressionType(COPY),
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: Some(VarnodeSimple::mock("const_0xCAFE_4")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_castop(&"0x1234".to_string());
}

#[test]
fn test_create_assign() {
    let op = PcodeOpSimple {
        pcode_index: 2,
        pcode_mnemonic: ExpressionType(COPY),
        input0: VarnodeSimple::mock("const_0x42_1"),
        input1: None,
        input2: None,
        output: Some(VarnodeSimple::mock("register_ZF_1")),
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
        input0: VarnodeSimple::mock("register_RAX_8"),
        input1: Some(VarnodeSimple::mock("const_0xCAFE_4")),
        input2: None,
        output: Some(VarnodeSimple::mock("register_RAX_8")),
    }
    .create_assign(&"0x1234".to_string());
}

#[test]
fn test_wrap_in_assign_or_store() {
    let mut op = mock_pcode_op_add(
        VarnodeSimple::mock("register_EAX_4"),
        Some(VarnodeSimple::mock("const_0xCAFE_4")),
        Some(VarnodeSimple::mock("register_EAX_4")),
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
    op.output = Some(VarnodeSimple::mock("ram_0x1234_4"));
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
        VarnodeSimple::mock("register_EAX_4"),
        Some(VarnodeSimple::mock("const_0xCAFE_4")),
        Some(VarnodeSimple::mock("const_0xFFFF_4")),
    )
    .wrap_in_assign_or_store(&"0x1234".to_string(), expr!("0x1111:4"));
}

#[test]
fn test_get_jump_target_relative() {
    // backwards jump is lower bounded to 0
    let var = VarnodeSimple::mock("const_0xFFFFFFFF_4");
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((0, 0))));

    let var = VarnodeSimple::mock("const_0x1_4");
    let op = mock_pcode_op_branch(7, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Relative((7, 8))));
}

#[test]
fn test_get_jump_target_absolute() {
    // backwards jump is lower bounded to 0
    let var = VarnodeSimple::mock("ram_0xFFFFFFFF_4");
    let op = mock_pcode_op_branch(0, var);
    assert_eq!(op.get_jump_target(), Some(JmpTarget::Absolute(0xFFFFFFFF)));
}

#[test]
fn collect_collect_jmp_targets() {
    todo!()
}

#[test]
fn collect_into_ir_def() {
    todo!()
}

#[test]
fn collect_create_def() {
    todo!()
}
