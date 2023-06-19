use super::*;
use crate::ghidra_pcode::PcodeOperation::ExpressionType;
use crate::pcode::ExpressionType::*;
use crate::{bitvec, def, expr, variable};

fn mock_varnode(addressspace: &str, id: &str, size: u64) -> VarnodeSimple {
    VarnodeSimple {
        address_space: addressspace.to_string(),
        id: id.to_string(),
        size,
    }
}

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
    fn set_varnodes(
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
fn test_varnode_into_const() {
    if let Expression::Const(c) = mock_varnode("const", "0x0", 8).into_ir_expr().unwrap() {
        assert_eq!(c, bitvec!("0x0:8"));
    } else {
        panic!("not an IR constant")
    }
    if let Expression::Const(c) = mock_varnode("const", "0x42", 4).into_ir_expr().unwrap() {
        assert_eq!(c, bitvec!("0x42:4"));
    } else {
        panic!("not an IR constant")
    }
}

#[test]
fn test_varnode_into_var() {
    if let Expression::Var(v) = mock_varnode("register", "RSP", 8).into_ir_expr().unwrap() {
        assert_eq!(v, variable!("RSP:8"));
    } else {
        panic!("not an IR variable")
    }
}

#[test]
fn test_varnode_into_temp_var() {
    if let Expression::Var(v) = mock_varnode("unique", "virtual", 8).into_ir_expr().unwrap() {
        assert_eq!(
            v,
            Variable {
                name: "$U_virtual".into(),
                size: 8.into(),
                is_temp: true
            }
        );
    } else {
        panic!("not an IR virtual variable")
    }
}

#[test]
fn test_varnode_alternative_addressspace() {
    assert!(mock_varnode("something", "id", 8).into_ir_expr().is_err());
}

#[test]
fn test_varnode_into_ram_address() {
    assert_eq!(
        mock_varnode("ram", "0xFF11", 8).get_ram_address(),
        Some(bitvec!("0xFF11:8"))
    );
}

#[test]
fn test_alternative_varnode_into_ram_address() {
    assert_eq!(
        mock_varnode("something", "0xFF11", 8).get_ram_address(),
        None
    );
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
            .set_varnodes(varnode.clone(), Some(ram_varnode.clone()), None, None)
            .has_implicit_load(),
        true
    );
    assert_eq!(
        pcode_op
            .clone()
            .set_varnodes(varnode.clone(), None, Some(ram_varnode.clone()), None)
            .has_implicit_load(),
        true
    );
    assert_eq!(
        pcode_op
            .clone()
            .set_varnodes(varnode.clone(), None, None, None)
            .has_implicit_load(),
        false
    );
    assert_eq!(
        pcode_op
            .clone()
            .set_varnodes(varnode.clone(), Some(varnode.clone()), None, None)
            .has_implicit_load(),
        false
    );
    assert_eq!(
        pcode_op
            .set_varnodes(varnode.clone(), None, Some(varnode.clone()), None)
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
