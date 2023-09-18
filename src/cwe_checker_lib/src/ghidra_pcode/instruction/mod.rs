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

    /// Collects all jump targets of an instruction and returns their `Tid`.
    /// The id follows the naming convention `blk_<address>`. If the target is within
    /// a pcode sequence and the index is larger 0, `_<pcode_index>` is suffixed.
    pub fn collect_jmp_and_fall_through_targets(
        &self,
        consecutive_instr: Option<&InstructionSimple>,
    ) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();
        for op in &self.pcode_ops {
            if matches!(op.pcode_mnemonic, PcodeOperation::JmpType(_)) {
                let targets = op.collect_jmp_targets(self);
                jump_targets.extend(targets);
                if let Some(fall_through) = op.get_fall_through_target(self) {
                    jump_targets.insert(fall_through);
                }
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
        pub fn mock<'a, T>(address: &'a str, pcode_ops: T) -> Self
        where
            T: IntoIterator,
            T::Item: Into<&'a str>,
        {
            let mut ops = Vec::new();
            for (index, op) in pcode_ops.into_iter().enumerate() {
                ops.push(PcodeOpSimple::mock(op.into()).with_index(index as u64));
            }
            InstructionSimple {
                mnemonic: "mock".into(),
                address: address.to_string(),
                size: 1,
                pcode_ops: ops,
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
        InstructionSimple::mock("0xABG".into(), Vec::<&str>::new()).get_u64_address();
    }
}
