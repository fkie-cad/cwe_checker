use super::ByteSize;
use crate::prelude::*;

/// A variable represents a register with a known size and name.
/// 
/// Variables can be temporary (or virtual).
/// In this case they do not represent actual physical registers
/// and are only used to store intermediate results necessary for representing more complex assembly instructions.
/// Temporary variables are only valid until the end of the current assembly instruction.
/// However, one assembly instruction may span more than one basic block in the intermediate representation
/// (but never more than one function).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
    pub name: String,
    pub size: ByteSize,
    pub is_temp: bool,
}
