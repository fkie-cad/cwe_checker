use super::Block;
use super::Varnode;
use crate::intermediate_representation::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Function {
    name: String,
    address: String,
    blocks: Vec<Block>,
}

impl Function {
    fn _into_ir_sub(self, _jump_targets: &HashSet<u64>) -> Term<Sub> {
        todo!()
    }

    pub fn blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    pub fn into_blocks(self) -> Vec<Block> {
        self.blocks
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternFunction {
    name: String,
    calling_convention: String,
    parameters: Vec<Varnode>,
    return_location: Option<Varnode>,
    thunks: Vec<String>,
    has_no_return: bool,
    has_var_args: bool,
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
