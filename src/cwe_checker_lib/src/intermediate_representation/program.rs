use super::{Blk, ExternSymbol, Sub};
use crate::prelude::*;
use std::collections::BTreeMap;

/// The `Program` structure represents a disassembled binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Program {
    /// The known functions contained in the binary
    pub subs: Vec<Term<Sub>>,
    /// Extern symbols linked to the binary by the linker.
    pub extern_symbols: BTreeMap<Tid, ExternSymbol>,
    /// Entry points into to binary,
    /// i.e. the term identifiers of functions that may be called from outside of the binary.
    pub entry_points: Vec<Tid>,
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
            .map(|sub| sub.term.blocks.iter())
            .flatten()
            .find(|block| block.tid == *tid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Program {
        pub fn mock_empty() -> Program {
            Program {
                subs: Vec::new(),
                extern_symbols: BTreeMap::new(),
                entry_points: Vec::new(),
                address_base_offset: 0,
            }
        }
    }
}
