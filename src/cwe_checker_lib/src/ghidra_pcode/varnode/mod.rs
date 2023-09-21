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
    /// Returns `Err` if the address space is neither `"const"`, `"register"` nor `"unique"`.
    pub fn into_ir_expr(&self) -> Result<Expression> {
        match self.address_space.as_str() {
            "const" => Ok(Expression::Const(self.to_const())),
            "register" | "unique" => Ok(Expression::Var(self.to_var())),
            _ => Err(anyhow!("Varnode translation failed.")),
        }
    }

    /// Translates a varnode with the "const" address space into the bitvector constant it represents.
    fn to_const(&self) -> Bitvector {
        assert_eq!(&self.address_space, "const");
        // FIXME: Does Ghidra produce constants larger than 8 bytes?
        // If yes, they could be parsed incorrectly by the current implementation.
        let constant =
            Bitvector::from_u64(u64::from_str_radix(self.id.trim_start_matches("0x"), 16).unwrap());
        constant.into_resize_unsigned(self.size.into())
    }

    /// Translates a varnode with the "register" or "unique" address space into a (regular or temporary) variable.
    fn to_var(&self) -> Variable {
        match self.address_space.as_str() {
            "register" => Variable {
                name: self.id.clone(),
                size: ByteSize::new(self.size),
                is_temp: false,
            },
            "unique" => Variable {
                name: format!("$U_{}", self.id),
                size: ByteSize::new(self.size),
                is_temp: true,
            },
            _ => panic!("Expected register or unique varnode."),
        }
    }

    /// Returns `Bitvector` representing a constant address in ram, if
    /// the varnode represents such address.
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

    /// Return the string representing a constant address in RAM
    /// if the varnode represents such an address.
    pub fn get_ram_address_as_string(&self) -> Option<&str> {
        if self.address_space.as_str() == "ram" {
            Some(&self.id)
        } else {
            None
        }
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
        let load_address = Expression::Const(
            self.get_ram_address()
                .expect("varnode's address space is not ram"),
        );
        // Change varnode to newly introduced explicit variable
        self.id = var_name.into();
        self.address_space = "unique".into();

        let load = Def::Load {
            var: self.to_var(),
            address: load_address,
        };
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
        /// Mock a varnode via a string on the form `AddressSpace_Id_Size`. Examples:
        /// - `register_RSP_8` for the `RAX` register.
        /// - `const_0x1_4` for a 4-byte-constant with value 1.
        pub fn mock(varnode: &str) -> Self {
            let components: Vec<_> = varnode.trim().split("_").collect();
            assert_eq!(components.len(), 3);
            for elem in &components {
                assert_eq!(*elem, elem.trim());
            }
            VarnodeSimple {
                address_space: components[0].to_string(),
                id: components[1].to_string(),
                size: u64::from_str_radix(components[2], 10).unwrap(),
            }
        }
    }

    #[test]
    fn test_varnode_mock() {
        let mock = VarnodeSimple::mock("const_0x1_16");
        let expected_varnode = VarnodeSimple {
            address_space: "const".to_string(),
            id: "0x1".to_string(),
            size: 16,
        };
        assert_eq!(mock, expected_varnode);
    }

    #[test]
    fn test_varnode_into_const() {
        assert_eq!(
            VarnodeSimple::mock("const_0x0_8").into_ir_expr().unwrap(),
            Expression::Const(bitvec!("0x0:8"))
        );
        assert_eq!(
            VarnodeSimple::mock("const_0x42_4").into_ir_expr().unwrap(),
            Expression::Const(bitvec!("0x42:4"))
        );
        assert_eq!(
            VarnodeSimple::mock("const_0xFFFFFFFF_4")
                .into_ir_expr()
                .unwrap(),
            Expression::Const(bitvec!("0x-1:4"))
        );
    }

    #[test]
    fn test_varnode_into_var() {
        assert_eq!(
            VarnodeSimple::mock("register_RSP_8")
                .into_ir_expr()
                .unwrap(),
            Expression::Var(variable!("RSP:8"))
        );
    }

    #[test]
    fn test_varnode_into_temp_var() {
        assert_eq!(
            VarnodeSimple::mock("unique_virtual_8")
                .into_ir_expr()
                .unwrap(),
            Expression::Var(Variable {
                name: "$U_virtual".into(),
                size: 8.into(),
                is_temp: true
            })
        );
    }

    #[test]
    fn test_varnode_alternative_address_space() {
        assert!(VarnodeSimple::mock("something_id_8")
            .into_ir_expr()
            .is_err());
    }

    #[test]
    fn test_varnode_into_ram_address() {
        assert_eq!(
            VarnodeSimple::mock("ram_0xFF11_8").get_ram_address(),
            Some(bitvec!("0xFF11:8"))
        );
        assert_eq!(
            VarnodeSimple::mock("something_0xFF11_8").get_ram_address(),
            None
        );
    }
}
