use super::PcodeOpSimple;
use super::PcodeOperation;
use crate::intermediate_representation::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct InstructionSimple {
    pub mnemonic: String,
    pub address: String,
    pub size: u64,
    pub pcode_ops: Vec<PcodeOpSimple>,
    pub potential_targets: Option<Vec<String>>,
    pub fall_through: Option<String>,
}

impl InstructionSimple {
    /// Returns the instruction field as `u64`.
    pub fn get_u64_address(&self) -> u64 {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16).unwrap()
    }

    /// Returns the fallthrough address of the instruction using the following order:
    /// 1) `instructions.fall_through` if `Some`
    /// 2) provided consecutive instruction's address
    /// 3) compute instructuins address + instruction size
    pub fn get_best_guess_fallthrough_addr(
        &self,
        consecutive_instr: Option<&InstructionSimple>,
    ) -> String {
        match &self.fall_through {
            Some(fallthrough_instr_addr) => fallthrough_instr_addr.clone(),
            // If no fallthrough information available, first try following instruction in block
            // else compute next instruction
            None => {
                if let Some(next_instr) = consecutive_instr {
                    next_instr.address.clone()
                } else {
                    // We have to ensure the same address format as used by Ghidra, even in the case of an integer overflow.
                    let formatted_address = format!(
                        "{:0width$x}",
                        self.get_u64_address() + self.size,
                        width = self.address.len() - 2
                    );
                    let formatted_address =
                        &formatted_address[(formatted_address.len() + 2 - self.address.len())..];
                    format!("0x{}", formatted_address)
                }
            }
        }
    }

    /// Collects all jump targets of an instruction and returns their `Tid`.
    /// The id follows the naming convention `blk_<address>`. If the target is within
    /// a pcode sequence and the index is larger 0, `_<pcode_index>` is suffixed.
    pub fn collect_jmp_targets(
        &self,
        consecutive_instr: Option<&InstructionSimple>,
    ) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();
        for op in &self.pcode_ops {
            if matches!(op.pcode_mnemonic, PcodeOperation::JmpType(_)) {
                let best_guess_fallthrough_address =
                    self.get_best_guess_fallthrough_addr(consecutive_instr);

                let targets = op.collect_jmp_targets(
                    self.address.clone(),
                    self.pcode_ops.len() as u64,
                    best_guess_fallthrough_address,
                );
                jump_targets.extend(targets)
            }
        }
        jump_targets
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl InstructionSimple {
        /// Returns `InstructionSimple`, with mnemonic `mock`, size `1`, `potential_targets` and `fall_through` set to `None`.
        pub fn mock(address: String, pcode_ops: Vec<PcodeOpSimple>) -> Self {
            InstructionSimple {
                mnemonic: "mock".into(),
                address: address,
                size: 1,
                pcode_ops: pcode_ops,
                potential_targets: None,
                fall_through: None,
            }
        }
    }

    #[test]
    fn test_instruction_get_u64_address() {
        let mut instr = InstructionSimple {
            mnemonic: "nop".into(),
            address: "0x00123ABFF".into(),
            size: 2,
            pcode_ops: vec![],
            potential_targets: None,
            fall_through: None,
        };
        assert_eq!(instr.get_u64_address(), 0x123ABFF);
        instr.address = "0x123ABFF".into();
        assert_eq!(instr.get_u64_address(), 0x123ABFF);
    }

    #[test]
    #[should_panic]
    fn test_instruction_get_u64_address_not_hex() {
        InstructionSimple::mock("0xABG".into(), vec![]).get_u64_address();
    }
}
