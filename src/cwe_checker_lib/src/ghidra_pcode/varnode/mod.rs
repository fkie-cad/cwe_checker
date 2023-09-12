use crate::intermediate_representation::*;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// The Varnode struct for deserialization of the ghidra pcode extractor JSON.
///
/// Varnode is a class used by ghidra for modeling a location within an addressspace and size, e.g. a specific
/// register.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct VarnodeSimple {
    /// Addressspace, e.g. register or constant
    pub address_space: String,
    /// Offset (value) in addressspace, or register name
    pub id: String,
    /// Size of the varnode
    pub size: u64,
}

impl VarnodeSimple {
    /// Translates into `Expression::Const` for constants or `Expression::Var` for registers or
    /// virtual registers.
    ///
    /// Returns `Err` if the addressspace is neither `"const"`, `"register"` nor `"unique"`.
    pub fn into_ir_expr(&self) -> Result<Expression> {
        match self.address_space.as_str() {
            "const" => {
                let constant =
                    Bitvector::from_u64(u64::from_str_radix(self.id.trim_start_matches("0x"), 16)?);
                Ok(Expression::Const(
                    constant.into_resize_unsigned(self.size.into()),
                ))
            }
            "register" => Ok(Expression::Var(Variable {
                name: self.id.clone(),
                size: ByteSize::new(self.size),
                is_temp: false,
            })),
            "unique" => Ok(Expression::Var(Variable {
                name: format!("$U_{}", self.id),
                size: ByteSize::new(self.size),
                is_temp: true,
            })),
            _ => Err(anyhow!("Varnode translation failed.")),
        }
    }

    /// Returns `Bitvector` representing a constant address in ram, if
    /// the varnode represents such address.
    /// Panics if the address cannot be parsed.
    pub fn get_ram_address(&self) -> Option<Bitvector> {
        if self.address_space.as_str() == "ram" {
            let offset = Bitvector::from_u64(
                u64::from_str_radix(self.id.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("Cannot parse {}", &self.id)),
            );
            return Some(offset.into_resize_unsigned(self.size.into()));
        }
        None
    }

    /// Returns `Term<Def::Load>`, if the varnode describes an implicit load operation.
    ///
    /// Changes the varnode's `id` and `address_space` to the virtual variable.
    ///
    /// Panics, if varnode's address_space is not `ram`
    pub fn into_explicit_load(
        &mut self,
        var_name: String,
        tid_suffix: String,
        address: &str,
        pcode_index: u64,
    ) -> Term<Def> {
        let load = Def::Load {
            var: Variable {
                name: var_name.clone(),
                size: self.size.into(),
                is_temp: true,
            },
            address: Expression::Const(
                self.get_ram_address()
                    .expect("varnode's addressspace is not ram"),
            ),
        };

        // Change varnode to newly introduced explicit variable
        self.id = var_name.into();
        self.address_space = "unique".into();

        Term {
            tid: Tid {
                id: format!("instr_{}_{}_{}", address, pcode_index, tid_suffix),
                address: address.to_string(),
            },
            term: load,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{bitvec, variable};

    impl VarnodeSimple {
        pub fn mock(addr_space: &str, id: &str, size: u64) -> Self {
            VarnodeSimple {
                address_space: addr_space.to_string(),
                id: id.to_string(),
                size,
            }
        }
    }

    #[test]
    fn test_varnode_into_const() {
        if let Expression::Const(c) = VarnodeSimple::mock("const", "0x0", 8)
            .into_ir_expr()
            .unwrap()
        {
            assert_eq!(c, bitvec!("0x0:8"));
        } else {
            panic!("not an IR constant")
        }
        if let Expression::Const(c) = VarnodeSimple::mock("const", "0x42", 4)
            .into_ir_expr()
            .unwrap()
        {
            assert_eq!(c, bitvec!("0x42:4"));
        } else {
            panic!("not an IR constant")
        }
        if let Expression::Const(c) = VarnodeSimple::mock("const", "0xFFFFFFFF", 4)
            .into_ir_expr()
            .unwrap()
        {
            assert_eq!(c, bitvec!("0x-1:4"));
        } else {
            panic!("not an IR constant")
        }
    }

    #[test]
    fn test_varnode_into_var() {
        if let Expression::Var(v) = VarnodeSimple::mock("register", "RSP", 8)
            .into_ir_expr()
            .unwrap()
        {
            assert_eq!(v, variable!("RSP:8"));
        } else {
            panic!("not an IR variable")
        }
    }

    #[test]
    fn test_varnode_into_temp_var() {
        if let Expression::Var(v) = VarnodeSimple::mock("unique", "virtual", 8)
            .into_ir_expr()
            .unwrap()
        {
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
        assert!(VarnodeSimple::mock("something", "id", 8)
            .into_ir_expr()
            .is_err());
    }

    #[test]
    fn test_varnode_into_ram_address() {
        assert_eq!(
            VarnodeSimple::mock("ram", "0xFF11", 8).get_ram_address(),
            Some(bitvec!("0xFF11:8"))
        );
    }

    #[test]
    fn test_alternative_varnode_into_ram_address() {
        assert_eq!(
            VarnodeSimple::mock("something", "0xFF11", 8).get_ram_address(),
            None
        );
    }
}
