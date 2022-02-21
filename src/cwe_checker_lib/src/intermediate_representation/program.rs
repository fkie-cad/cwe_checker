use super::{Blk, ExternSymbol, Sub};
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// The `Program` structure represents a disassembled binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Program {
    /// The known functions contained in the binary
    pub subs: BTreeMap<Tid, Term<Sub>>,
    /// Extern symbols linked to the binary by the linker.
    pub extern_symbols: BTreeMap<Tid, ExternSymbol>,
    /// Entry points into to binary,
    /// i.e. the term identifiers of functions that may be called from outside of the binary.
    pub entry_points: BTreeSet<Tid>,
    /// An offset that has been added to all addresses in the program compared to the addresses
    /// as specified in the binary file.
    ///
    /// In certain cases, e.g. if the binary specifies a segment to be loaded at address 0,
    /// the Ghidra backend may shift the whole binary image by a constant value in memory.
    /// Thus addresses as specified by the binary and addresses as reported by Ghidra may differ by a constant offset,
    /// which is stored in this value.
    pub address_base_offset: u64,
}

impl Program {
    /// Find a block term by its term identifier.
    /// WARNING: The function simply iterates through all blocks,
    /// i.e. it is very inefficient for large projects!
    pub fn find_block(&self, tid: &Tid) -> Option<&Term<Blk>> {
        self.subs
            .iter()
            .map(|(_, sub)| sub.term.blocks.iter())
            .flatten()
            .find(|block| block.tid == *tid)
    }
}

#[cfg(test)]
mod tests {
    use crate::intermediate_representation::{Arg, CallingConvention, Datatype};

    use super::*;

    impl Program {
        /// Returns Program with malloc, free and other_function
        pub fn mock_x64() -> Program {
            let malloc = ExternSymbol {
                tid: Tid::new("malloc"),
                addresses: vec![],
                name: "malloc".to_string(),
                calling_convention: Some("__stdcall".to_string()),
                parameters: vec![Arg::from_var(
                    CallingConvention::mock_x64().integer_parameter_register[0].clone(),
                    Some(Datatype::Integer),
                )],
                return_values: vec![Arg::from_var(
                    CallingConvention::mock_x64().integer_return_register[0].clone(),
                    Some(Datatype::Pointer),
                )],
                no_return: false,
                has_var_args: false,
            };
            let free = ExternSymbol {
                tid: Tid::new("free"),
                addresses: vec![],
                name: "free".to_string(),
                calling_convention: Some("__stdcall".to_string()),
                parameters: vec![Arg::from_var(
                    CallingConvention::mock_x64().integer_parameter_register[0].clone(),
                    Some(Datatype::Pointer),
                )],
                return_values: vec![],
                no_return: false,
                has_var_args: false,
            };
            let other_function = ExternSymbol {
                tid: Tid::new("other_function"),
                addresses: vec![],
                name: "other_function".to_string(),
                calling_convention: None,
                parameters: vec![],
                return_values: vec![],
                no_return: false,
                has_var_args: false,
            };

            Program {
                subs: BTreeMap::new(),
                extern_symbols: BTreeMap::from([
                    (malloc.tid.clone(), malloc),
                    (free.tid.clone(), free),
                    (other_function.tid.clone(), other_function),
                ]),
                entry_points: BTreeSet::new(),
                address_base_offset: 0x1000u64,
            }
        }
        /// Returns Program with malloc, free and other_function
        pub fn mock_arm32() -> Program {
            // Creates arm32 program by altering x64 program
            let mut prog = Program::mock_x64();
            for symbol in prog.extern_symbols.values_mut() {
                if symbol.name == "malloc".to_string() {
                    symbol.parameters = vec![Arg::from_var(
                        CallingConvention::mock_arm32().integer_parameter_register[0].clone(),
                        Some(Datatype::Integer),
                    )];
                    symbol.return_values = vec![Arg::from_var(
                        CallingConvention::mock_arm32().integer_return_register[0].clone(),
                        Some(Datatype::Pointer),
                    )];
                }
                if symbol.name == "free".to_string() {
                    symbol.parameters = vec![Arg::from_var(
                        CallingConvention::mock_arm32().integer_parameter_register[0].clone(),
                        Some(Datatype::Pointer),
                    )];
                }
            }
            prog
        }
    }
}
