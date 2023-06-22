use super::*;
use crate::{bitvec, variable};

pub fn mock_varnode(addressspace: &str, id: &str, size: u64) -> VarnodeSimple {
    VarnodeSimple {
        address_space: addressspace.to_string(),
        id: id.to_string(),
        size,
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
