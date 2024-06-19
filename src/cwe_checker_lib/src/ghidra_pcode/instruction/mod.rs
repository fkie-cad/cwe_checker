use super::PcodeOp;
use super::PcodeOperation;
use crate::intermediate_representation::*;
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fmt::{self, Display};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Instruction {
    mnemonic: String,
    address: String,
    size: u64,
    pcode_ops: Vec<PcodeOp>,
    potential_targets: Option<Vec<String>>,
    fall_through: Option<String>,
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} {}", self.address, self.size, self.mnemonic)?;
        if let Some(potential_targets) = &self.potential_targets {
            write!(f, " [")?;
            for target in potential_targets.iter() {
                write!(f, " {}", target)?;
            }
            write!(f, "]")?;
        }
        if let Some(fall_through) = &self.fall_through {
            write!(f, " -> {}", fall_through)?;
        }
        writeln!(f, "")?;
        for pcode_op in &self.pcode_ops {
            writeln!(f, "\t{}", pcode_op)?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
impl Instruction {
    pub fn address(&self) -> &String {
        &self.address
    }

    pub fn mnemonic(&self) -> &String {
        &self.mnemonic
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn pcode_ops(&self) -> &Vec<PcodeOp> {
        &self.pcode_ops
    }

    pub fn potential_targets(&self) -> Option<&Vec<String>> {
        self.potential_targets.as_ref()
    }

    pub fn fall_through(&self) -> Option<&String> {
        self.fall_through.as_ref()
    }

    /// Returns the instruction field as `u64`.
    pub fn get_u64_address(&self) -> u64 {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16).unwrap()
    }

    /// Collects all jump targets of an instruction and returns their `Tid`.
    /// The id follows the naming convention `blk_<address>`. If the target is within
    /// a pcode sequence and the index is larger 0, `_<pcode_index>` is suffixed.
    pub fn collect_jmp_and_fall_through_targets(
        &self,
        _consecutive_instr: Option<&Instruction>,
    ) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();
        for op in &self.pcode_ops {
            if matches!(op.operator(), PcodeOperation::JmpType(_)) {
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

    impl Instruction {
        /// Returns `InstructionSimple`, with mnemonic `mock`, size `1`, `potential_targets` and `fall_through` set to `None`.
        pub fn mock<'a, T>(address: &'a str, pcode_ops: T) -> Self
        where
            T: IntoIterator,
            T::Item: Into<&'a str>,
        {
            let mut ops = Vec::new();
            for (index, op) in pcode_ops.into_iter().enumerate() {
                ops.push(PcodeOp::mock(op.into()).with_index(index as u64));
            }
            Instruction {
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
        let mut instr = Instruction {
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
        Instruction::mock("0xABG".into(), Vec::<&str>::new()).get_u64_address();
    }
}
