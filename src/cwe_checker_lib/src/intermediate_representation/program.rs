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
        /// Returns extern symbol with argument/return register according to calling convention
        fn create_extern_symbol(
            name: &str,
            cconv: CallingConvention,
            arg_type: Option<Datatype>,
            return_type: Option<Datatype>,
        ) -> ExternSymbol {
            ExternSymbol {
                tid: Tid::new(name),
                addresses: vec![],
                name: name.to_string(),
                calling_convention: Some(cconv.name),
                parameters: match arg_type {
                    Some(data_type) => {
                        vec![Arg::from_var(
                            cconv.integer_parameter_register[0].clone(),
                            Some(data_type),
                        )]
                    }
                    None => vec![],
                },
                return_values: match return_type {
                    Some(data_type) => {
                        vec![Arg::from_var(
                            cconv.integer_return_register[0].clone(),
                            Some(data_type),
                        )]
                    }
                    None => vec![],
                },
                no_return: false,
                has_var_args: false,
            }
        }

        fn add_extern_symbols_to_program(a: Vec<(Tid, ExternSymbol)>) -> Program {
            Program {
                subs: BTreeMap::new(),
                extern_symbols: BTreeMap::from_iter(a),
                entry_points: BTreeSet::new(),
                address_base_offset: 0x1000u64,
            }
        }
        /// Returns Program with malloc, free and other_function
        pub fn mock_x64() -> Program {
            let malloc = Program::create_extern_symbol(
                "malloc",
                CallingConvention::mock_x64(),
                Some(Datatype::Integer),
                Some(Datatype::Pointer),
            );
            let free = Program::create_extern_symbol(
                "free",
                CallingConvention::mock_x64(),
                Some(Datatype::Pointer),
                None,
            );
            let other_function = Program::create_extern_symbol(
                "other_function",
                CallingConvention::mock_x64(),
                None,
                None,
            );

            Program::add_extern_symbols_to_program(vec![
                (malloc.tid.clone(), malloc),
                (free.tid.clone(), free),
                (other_function.tid.clone(), other_function),
            ])
        }
        /// Returns Program with malloc, free and other_function
        pub fn mock_arm32() -> Program {
            let malloc = Program::create_extern_symbol(
                "malloc",
                CallingConvention::mock_arm32(),
                Some(Datatype::Integer),
                Some(Datatype::Pointer),
            );
            let free = Program::create_extern_symbol(
                "free",
                CallingConvention::mock_arm32(),
                Some(Datatype::Pointer),
                None,
            );
            let other_function = Program::create_extern_symbol(
                "other_function",
                CallingConvention::mock_arm32(),
                None,
                None,
            );

            Program::add_extern_symbols_to_program(vec![
                (malloc.tid.clone(), malloc),
                (free.tid.clone(), free),
                (other_function.tid.clone(), other_function),
            ])
        }
    }
}
