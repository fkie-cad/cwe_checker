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

/// Mock a temporary variable
fn mock_temp_var(var: &str) -> Variable {
    let components: Vec<_> = var.split(":").collect();
    Variable {
        name: components[0].to_string(),
        size: u64::from_str_radix(components[1], 10).unwrap().into(),
        is_temp: true,
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
    // Implicit loads for input0 and input1
    let mut instr = InstructionSimple::mock("0x1000", ["ram_0x10_8 INT_SUB ram_0x20_8 ram_0x30_8"]);
    let expected_load0 = Term {
        tid: Tid::mock("instr_0x1000_0_load0"),
        term: Def::Load {
            var: mock_temp_var("$load_temp0:8"),
            address: expr!("0x20:8"),
        },
    };
    let expected_load1 = Term {
        tid: Tid::mock("instr_0x1000_0_load1"),
        term: Def::Load {
            var: mock_temp_var("$load_temp1:8"),
            address: expr!("0x30:8"),
        },
    };
    assert_eq!(
        instr.pcode_ops[0].create_implicit_loads_for_def("0x1000"),
        vec![expected_load0, expected_load1]
    );
    assert_eq!(
        &instr.pcode_ops[0].input0,
        &VarnodeSimple {
            address_space: "unique".to_string(),
            id: "$load_temp0".to_string(),
            size: 8
        }
    );
    assert_eq!(
        instr.pcode_ops[0].input1.as_ref().unwrap(),
        &VarnodeSimple {
            address_space: "unique".to_string(),
            id: "$load_temp1".to_string(),
            size: 8
        }
    );
    // Implicit load for input2
    let mut instr = InstructionSimple::mock(
        "0x1000",
        ["register_RAX_8 STORE const_0x10_8 register_RAX_8 ram_0x10_8"],
    );
    let expected_load = Term {
        tid: Tid::mock("instr_0x1000_0_load2"),
        term: Def::Load {
            var: mock_temp_var("$load_temp2:8"),
            address: expr!("0x10:8"),
        },
    };
    assert_eq!(
        instr.pcode_ops[0].create_implicit_loads_for_def("0x1000"),
        vec![expected_load]
    );
    assert_eq!(
        instr.pcode_ops[0].input2.as_ref().unwrap(),
        &VarnodeSimple {
            address_space: "unique".to_string(),
            id: "$load_temp2".to_string(),
            size: 8
        }
    );
    // No implicit load
    let mut instr = InstructionSimple::mock(
        "0x1000",
        ["register_RAX_8 STORE const_0x10_8 register_RAX_8 register_RAX_8"],
    );
    assert_eq!(
        instr.pcode_ops[0].create_implicit_loads_for_def("0x1000"),
        vec![]
    );
}

#[test]
fn test_create_load() {
    let pcode_op = PcodeOpSimple::mock("register_RAX_8 LOAD space_id_8 const_0x0012345_8");
    assert_eq!(
        pcode_op.create_load(&"0xFFFFFF".to_string()),
        Term {
            tid: Tid::mock("instr_0xFFFFFF_0"),
            term: def!["RAX:8 := Load from 0x0012345:8"].term
        }
    );
}

#[test]
#[should_panic]
fn test_create_load_no_source() {
    PcodeOpSimple::mock("register_RAX_8 LOAD space_id_8").create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_no_output() {
    PcodeOpSimple::mock("LOAD space_id_8 const_0x200_8").create_load(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_load_target_not_var() {
    PcodeOpSimple::mock("const_0x4321_8 LOAD space_id_8 const_0x200_8")
        .create_load(&"0x123".to_string());
}

#[test]
fn test_create_store() {
    let pcode_op = PcodeOpSimple::mock("STORE space_id_8 register_RAX_8 const_0x42_8");
    assert_eq!(
        pcode_op.create_store(&"0x00ABCDEF".to_string()),
        Term {
            tid: Tid::mock("instr_0x00ABCDEF_0"),
            term: def!["Store at RAX:8 := 0x42:8"].term
        }
    )
}

#[test]
#[should_panic]
fn test_create_store_not_store() {
    PcodeOpSimple::mock("STORE space_id_8 register_RAX_8").create_store(&"0x123".to_string());
}

#[test]
#[should_panic]
fn test_create_store_from_ram() {
    PcodeOpSimple::mock("STORE space_id_8 const_4321_8 ram_0xFFFF01_8")
        .create_store(&"0x123".to_string());
}

#[test]
fn test_create_subpiece() {
    let op = PcodeOpSimple::mock("register_EAX_4 SUBPIECE const_0xAABBCCDD_8 const_0x3_1");
    let expected_expr = Expression::Subpiece {
        low_byte: 3.into(),
        size: 4.into(),
        arg: Box::new(Expression::Const(Bitvector::from_u64(0xAABBCCDD))),
    };
    let expected = Term {
        tid: Tid::mock("instr_0x1234_0"),
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
    PcodeOpSimple::mock("register_EAX_4 SUBPIECE const_0xABCDEF_8 register_RAX_8")
        .create_subpiece(&"0x1234".to_string());
}

#[test]
fn test_create_unop() {
    let op = PcodeOpSimple::mock("register_RAX_8 INT_NEGATE register_RAX_8");
    let mut expected = def!["instr_0x1234_0: RAX:8 = -(RAX:8)"];
    expected.tid.address = "0x1234".to_string();
    assert_eq!(op.create_unop(&"0x1234".to_string()), expected);
}

#[test]
#[should_panic]
fn test_create_unop_not_expression_type() {
    PcodeOpSimple::mock("register_RAX_8 CALL register_RAX_8").create_unop(&"0xFFFF".to_string());
}

#[test]
#[should_panic]
fn test_create_unop_not_unop_type() {
    PcodeOpSimple::mock("register_RAX_8 INT_ADD register_RAX_8").create_unop(&"0xFFFF".to_string());
}

#[test]
fn test_create_biop() {
    let op = PcodeOpSimple::mock("register_RAX_8 INT_ADD register_RAX_8 const_0xCAFE_8");
    let expected = Term {
        tid: Tid::mock("instr_0x1234_0"),
        term: def!["RAX:8 = RAX:8 + 0xCAFE:4"].term,
    };
    assert_eq!(op.create_biop(&"0x1234".to_string()), expected)
}

#[test]
#[should_panic]
fn test_create_biop_not_biop_type() {
    PcodeOpSimple::mock("register_RAX_8 COPY register_RAX_8 const_0xCAFE_8")
        .create_biop(&"0x1234".to_string());
}

#[test]
fn test_create_cast_op() {
    let op = PcodeOpSimple::mock("register_RDI_8 INT_ZEXT const_0x1_1");
    let expected_expr = Expression::Cast {
        op: CastOpType::IntZExt,
        size: 8.into(),
        arg: Box::new(expr!("0x1:1")),
    };
    let expected = Term {
        tid: Tid::mock("instr_0x4321_0"),
        term: Def::Assign {
            var: variable!("RDI:8"),
            value: expected_expr,
        },
    };
    assert_eq!(op.create_castop(&"0x4321".to_string()), expected);
}

#[test]
#[should_panic]
fn test_create_castop_not_castop_type() {
    PcodeOpSimple::mock("register_RAX_8 COPY const_0x1_1").create_castop(&"0x1234".to_string());
}

#[test]
fn test_create_assign() {
    let op = PcodeOpSimple::mock("register_ZF_1 COPY const_0x1_1");
    let expected = Term {
        tid: Tid::mock("instr_0x1111_0"),
        term: def!["ZF:1 = 0x1:1"].term,
    };
    assert_eq!(expected, op.create_assign(&"0x1111".to_string()))
}

#[test]
#[should_panic]
fn test_create_assign_not_copy_type() {
    PcodeOpSimple::mock("register_ZF_1 BOOL_AND register_RAX_8 const_0xCAFE_4")
        .create_assign(&"0x1234".to_string());
}

#[test]
fn test_wrap_in_assign_or_store() {
    let op = PcodeOpSimple::mock("register_EAX_4 INT_ADD register_EAX_4 const_0xCAFE_4");
    let expr = expr!("EAX:4 + 0xCAFE:4");
    // test Assign
    let mut expected = Term {
        tid: Tid::mock("instr_0x1234_0"),
        term: def!["EAX:4 = EAX:4 + 0xCAFE:4"].term,
    };
    assert_eq!(
        expected,
        op.wrap_in_assign_or_store(&"0x1234".to_string(), expr.clone())
    );
    // test Store
    let op = PcodeOpSimple::mock("ram_0x1000_4 INT_ADD register_EAX_4 const_0xCAFE_4");
    expected.term = def!["Store at 0x1000:4 := EAX:4 + 0xCAFE:4"].term;
    assert_eq!(
        op.wrap_in_assign_or_store(&"0x1234".to_string(), expr),
        expected
    )
}

#[test]
#[should_panic]
fn test_wrap_in_assign_or_store_output_not_variable_nor_implicit_store() {
    PcodeOpSimple::mock("const_0xFFFF_4 INT_ADD register_EAX_4 const_0xCAFE_4")
        .wrap_in_assign_or_store(&"0x1234".to_string(), expr!("0x1111:4"));
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
