use super::BlockSimple;
use super::VarnodeSimple;
use crate::intermediate_representation::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FunctionSimple {
    pub name: String,
    pub address: String,
    pub blocks: Vec<BlockSimple>,
}

impl FunctionSimple {
    fn into_ir_sub(self, jump_targets: &HashSet<u64>) -> Term<Sub> {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternFunctionSimple {
    pub name: String,
    pub calling_convention: String,
    pub parameters: Vec<VarnodeSimple>,
    pub return_location: Option<VarnodeSimple>,
    pub thunks: Vec<String>,
    pub has_no_return: bool,
    pub has_var_args: bool,
}

/// Generate a TID for a function at the given address.
/// Note that the actual TID of the function at the given address may be different
/// depending on the function name provided by Ghidra.
pub fn generate_placeholder_function_tid(address: &str) -> Tid {
    Tid {
        id: format!("FUN_{}", address),
        address: address.to_string(),
    }
}
