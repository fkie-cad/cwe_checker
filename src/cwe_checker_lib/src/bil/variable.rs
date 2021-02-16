use super::BitSize;
use crate::intermediate_representation::Variable as IrVariable;
use crate::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Variable {
    pub name: String,
    pub type_: Type,
    pub is_temp: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Type {
    Immediate(BitSize),
    Memory {
        addr_size: BitSize,
        elem_size: BitSize,
    },
    Unknown,
}

impl Type {
    pub fn bitsize(&self) -> Result<BitSize, Error> {
        if let Type::Immediate(bitsize) = self {
            Ok(*bitsize)
        } else {
            Err(anyhow!("Not a register type"))
        }
    }
}

impl Variable {
    pub fn bitsize(&self) -> Result<BitSize, Error> {
        self.type_.bitsize()
    }
}

impl From<Variable> for IrVariable {
    fn from(var: Variable) -> IrVariable {
        let size = if let Type::Immediate(bitsize) = var.type_ {
            bitsize.into()
        } else {
            panic!()
        };
        IrVariable {
            name: var.name,
            size,
            is_temp: var.is_temp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_deserialization() {
        let typ = Type::Immediate(64);
        let string = serde_json::to_string_pretty(&typ).expect("Serialization failed");
        println!("{}", &string);
        let _: Type = serde_json::from_str(&string).expect("Deserialization failed");
        let typ = Type::Memory {
            addr_size: 64,
            elem_size: 8,
        };
        let string = serde_json::to_string_pretty(&typ).expect("Serialization failed");
        println!("{}", &string);
        let _: Type = serde_json::from_str(&string).expect("Deserialization failed");
        let typ = Type::Unknown;
        let string = serde_json::to_string_pretty(&typ).expect("Serialization failed");
        println!("{}", &string);
        let _: Type = serde_json::from_str(&string).expect("Deserialization failed");
    }

    #[test]
    fn var_type_from_ocaml() {
        let json_string = "{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}";
        let typ = Type::Memory {
            addr_size: 64,
            elem_size: 8,
        };
        assert_eq!(typ, serde_json::from_str(json_string).unwrap())
    }

    #[test]
    fn var_from_ocaml() {
        let json_string = "{\"is_temp\":false,\"name\":\"RAX\",\"type_\":{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}}";
        let var = Variable {
            name: "RAX".to_string(),
            type_: Type::Memory {
                addr_size: 64,
                elem_size: 8,
            },
            is_temp: false,
        };
        assert_eq!(var, serde_json::from_str(json_string).unwrap())
    }
}
