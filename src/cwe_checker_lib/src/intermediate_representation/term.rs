//! Unique term identifiers.

use crate::prelude::*;

use std::convert::{From, TryFrom};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

use anyhow;

mod builder_high_lvl;
mod builder_low_lvl;

/// A unique term identifier.
///
/// A `Tid` consists of an ID string (which is required to be unique)
/// and an address to indicate where the term is located in memory.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct Tid {
    /// The unique ID of the term.
    id: String,
    /// The address where the term is located.
    address: TidAddress,
}
// TODO: Eventually we want those to be proper Newtypes. Common behavior should
// be moved to a `Tid` trait.
/// Identifier of a program term.
pub type ProgramTid = Tid;
/// Identifier of a function term.
pub type FunctionTid = Tid;
/// Identifier of an external function term.
pub type ExtFunctionTid = Tid;
/// Identifier of a block term.
pub type BlockTid = Tid;
/// Identifier of an instruction term.
pub type InstructionTid = Tid;

/// The memory address of a term.
///
/// Multiple terms may be at the same address. Some terms may be at an unknown
/// address.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Copy, Clone, PartialOrd, Ord)]
pub struct TidAddress(Option<u64>);

impl Display for TidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(a) => write!(f, "{:x}", a),
            None => write!(f, "{}", Tid::UNKNOWN_ADDRESS),
        }
    }
}

impl<T: AsRef<str>> From<T> for TidAddress {
    fn from(a: T) -> Self {
        let addr = u64::from_str_radix(a.as_ref().trim_start_matches("0x"), 16);

        Self(addr.ok())
    }
}

impl TryFrom<TidAddress> for u64 {
    type Error = anyhow::Error;

    fn try_from(a: TidAddress) -> Result<u64, Self::Error> {
        a.0.ok_or(anyhow::anyhow!("Term is at unknown address."))
    }
}

impl TidAddress {
    /// Returns a new `TidAddress`.
    pub fn new(a: Option<u64>) -> Self {
        Self(a)
    }

    /// Returns true iff the address is unknown.
    pub fn is_unknown(&self) -> bool {
        self.0.is_none()
    }
}

impl Tid {
    /// Prefix for TIDs of artificial sinks in the control flow graph.
    ///
    /// Dummy blocks with such TIDs are added if our recovered control flow is
    /// incomplete, e.g., branches to nonexistent targets.
    const ARTIFICIAL_SINK_BLOCK_ID_PREFIX: &'static str = "artificial_sink_block";
    /// Prefix for TIDs of artificial instructions.
    const ARTIFICIAL_INSTRUCTION_ID_PREFIX: &'static str = "artificial_instruction";
    /// Prefix for TIDs of artificial return targets in the control flow graph.
    ///
    /// Dummy blocks with such TIDs are added as return targets for calls to
    /// non-returning functions.
    const ARTIFICIAL_RETURN_TARGET_ID_PREFIX: &'static str = "artificial_return_target";
    /// The TID of the artificial sink sub.
    ///
    /// This is used as the target for calls to non-existing or empty functions.
    const ARTIFICIAL_SINK_FN_ID: &'static str = "artificial_sink_sub";
    /// Address for use in TIDs of terms that do not have an address, e.g.,
    /// artificial blocks.
    const UNKNOWN_ADDRESS: &'static str = "UNKNOWN";
    const PROGRAM_ID_PREFIX: &'static str = "prog";
    const FUNCTION_ID_PREFIX: &'static str = "fun";
    const EXT_FUNCTION_ID_PREFIX: &'static str = "ext_fun";
    const BLOCK_ID_PREFIX: &'static str = "blk";
    const INSTRUCTION_ID_PREFIX: &'static str = "instr";

    /// Returns the term identifier for the program that is based at the
    /// given `address`.
    pub fn new_program<T: Into<TidAddress> + Display>(address: T) -> Self {
        Self {
            id: format!("{}_{}", Self::PROGRAM_ID_PREFIX, address),
            address: address.into(),
        }
    }

    /// Returns the TID for the function at the given address.
    pub fn new_function<T: Into<TidAddress> + Display>(address: T) -> Self {
        Self {
            id: format!("{}_{}", Self::FUNCTION_ID_PREFIX, address),
            address: address.into(),
        }
    }

    /// Returns the TID for the external function with the given name.
    pub fn new_external_function<T: Display + ?Sized>(name: &T) -> Self {
        Self {
            id: format!("{}_{}", Self::EXT_FUNCTION_ID_PREFIX, name),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Generate a new term identifier for the block with `index` at `address`.
    pub fn new_block<T: Into<TidAddress> + Display>(address: T, index: u64) -> Self {
        let id = match index {
            0 => format!("{}_{}", Self::BLOCK_ID_PREFIX, address),
            _ => format!("{}_{}_{}", Self::BLOCK_ID_PREFIX, address, index),
        };

        Self {
            id,
            address: address.into(),
        }
    }

    /// Generate a new term identifier for the instruction with `index` at
    /// `address`.
    pub fn new_instr<T: Into<TidAddress> + Display>(address: T, index: u64) -> Self {
        Tid::new_instr_with_suffix::<_, &str>(address, index, None)
    }

    /// Converts TID into a TID for an instruction at the same address.
    pub fn into_instr(self) -> Self {
        Self {
            id: format!("{}_{}_0", Self::INSTRUCTION_ID_PREFIX, self.address),
            address: self.address,
        }
    }

    /// Generate a new term identifier for the instruction with `index` at
    /// `address`.
    pub fn new_instr_with_suffix<T, U>(address: T, index: u64, suffix: Option<&U>) -> Self
    where
        T: Display + Into<TidAddress>,
        U: Display + ?Sized,
    {
        match suffix {
            Some(suffix) => Self {
                id: format!(
                    "{}_{}_{}_{}",
                    Self::INSTRUCTION_ID_PREFIX,
                    address,
                    index,
                    suffix
                ),
                address: address.into(),
            },
            None => Self {
                id: format!("{}_{}_{}", Self::INSTRUCTION_ID_PREFIX, address, index),
                address: address.into(),
            },
        }
    }

    /// Returns true iff this is a TID for a program.
    pub fn is_program(&self) -> bool {
        self.id.starts_with(Self::PROGRAM_ID_PREFIX)
    }

    /// Returns true iff this is a TID for a function.
    pub fn is_function(&self) -> bool {
        self.id.starts_with(Self::FUNCTION_ID_PREFIX)
    }

    /// Returns true iff this is a TID for an external function.
    pub fn is_external_function(&self) -> bool {
        self.id.starts_with(Self::EXT_FUNCTION_ID_PREFIX)
    }

    /// Returns true iff this is a TID for a block.
    pub fn is_block(&self) -> bool {
        self.id.starts_with(Self::BLOCK_ID_PREFIX)
    }

    /// Returns true iff this is a TID for a block that is starting at an
    /// architectural instruction boundary.
    pub fn is_block_without_suffix(&self) -> bool {
        self.is_block() && self.id.split('_').count() == 2
    }

    /// Returns true iff this is a TID for a block.
    pub fn is_instruction(&self) -> bool {
        self.id.starts_with(Self::INSTRUCTION_ID_PREFIX)
    }

    /// Add a suffix to the ID string and return the new `Tid`
    pub fn with_id_suffix(self, suffix: &str) -> Self {
        Tid {
            id: self.id + suffix,
            address: self.address,
        }
    }

    /// Returns true if the ID string ends with the provided suffix.
    pub fn has_id_suffix(&self, suffix: &str) -> bool {
        self.id.ends_with(suffix)
    }

    /// Returns the ID of the artificial sink function.
    pub fn artificial_sink_fn() -> Self {
        Self {
            id: Self::ARTIFICIAL_SINK_FN_ID.to_string(),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns a new ID for an artificial sink block with the given suffix.
    pub fn artificial_sink_block<T: Display>(suffix: T) -> Self {
        Self {
            id: format!("{}{}", Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX, suffix),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns a new ID for the artificial sink block of the given funtion.
    pub fn artificial_sink_block_for_fn(fn_tid: &Tid) -> Self {
        Self {
            id: format!("{}_{}", Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX, fn_tid),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns a new ID for the artificial sink block with the given suffix.
    pub fn artificial_return_target<T: Display>(suffix: T) -> Self {
        Self {
            id: format!("{}{}", Self::ARTIFICIAL_RETURN_TARGET_ID_PREFIX, suffix),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns a new ID for the artificial sink block of the given funtion.
    pub fn artificial_return_target_for_fn(fn_tid: &Tid) -> Self {
        Self {
            id: format!("{}_{}", Self::ARTIFICIAL_RETURN_TARGET_ID_PREFIX, fn_tid),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns a new ID for an artificial instruction with the given suffix.
    pub fn artificial_instr_with_suffix<T: Display>(suffix: T) -> Self {
        Self {
            id: format!("{}{}", Self::ARTIFICIAL_INSTRUCTION_ID_PREFIX, suffix),
            address: Self::UNKNOWN_ADDRESS.into(),
        }
    }

    /// Returns true iff the ID is for the artificial sink sub.
    pub fn is_artificial_sink_fn(&self) -> bool {
        self.id == Self::ARTIFICIAL_SINK_FN_ID && self.address.is_unknown()
    }

    /// Returns true iff the ID is for an artificial sink block.
    pub fn is_artificial_sink_block(&self) -> bool {
        self.id.starts_with(Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX) && self.address.is_unknown()
    }

    /// Returns true iff the ID is for the artificial sink block with the given
    /// suffix.
    pub fn is_artificial_sink_block_for(&self, suffix: &str) -> bool {
        self.id.starts_with(Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX)
            && self.has_id_suffix(suffix)
            && self.address.is_unknown()
    }

    /// Returns true iff the ID is for an artificial return target block.
    pub fn is_artificial_return_target_block(&self) -> bool {
        self.id
            .starts_with(Self::ARTIFICIAL_RETURN_TARGET_ID_PREFIX)
            && self.address.is_unknown()
    }

    /// Returns the address of this TID.
    pub fn address(&self) -> TidAddress {
        self.address
    }
}

impl std::fmt::Display for Tid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

/// A term is an object inside a binary with an address and an unique ID
/// (both contained in the [`Tid`]).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term<T> {
    /// The term identifier, which also contains the address of the term.
    pub tid: Tid,
    /// The object.
    pub term: T,
}

impl<T: Display> Display for Term<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.tid, self.term)
    }
}

impl<T> Deref for Term<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.term
    }
}

impl<T> DerefMut for Term<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.term
    }
}

impl<T> AsRef<T> for Term<T> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T> AsMut<T> for Term<T> {
    fn as_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T> Term<T> {
    /// Returns a new `Term`.
    pub fn new(tid: Tid, term: T) -> Self {
        Self { tid, term }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl Tid {
        /// Returns a new TID with the given ID at the unknown address.
        pub fn new<T: ToString>(id: T) -> Self {
            Self {
                id: id.to_string(),
                address: TidAddress(None),
            }
        }

        /// Set the address of the TID.
        pub fn set_address<T: Into<TidAddress>>(&mut self, addr: T) {
            self.address = addr.into();
        }

        /// Mock a TID with the given name and the address parsed from the name.
        /// The name must have the form `prefix_address[_suffix]`, e.g. `instr_0x00001234_5`.
        pub fn mock(tid: &str) -> Tid {
            let components: Vec<_> = tid.split("_").collect();
            Tid {
                id: tid.to_string(),
                address: components[1].into(),
            }
        }
    }
}
