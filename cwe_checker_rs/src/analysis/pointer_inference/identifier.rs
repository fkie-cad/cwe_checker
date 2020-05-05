use crate::prelude::*;
use crate::bil::variable::*;
use crate::utils::fast_cmp_arc::FastCmpArc;
use std::sync::Arc;

// TODO: Right now abstract locations are used as giving the location where a pointer to an object is located.
// But it could also be used to point into the object (at offset 0).
// Can I solve this possible ambivalence in intended usage in a way such that accidentally wrong usage is prevented?
// If not, I have to document the intended usage with a big warning sign.

/// An abstract identifier is given by a time identifier and a location identifier.
///
/// For the location identifier see `AbstractLocation`.
/// The time identifier is given by a `Tid`.
/// If it is the Tid of a basic block, then it describes the point in time *before* execution of the first instruction in the block.
/// If it is the Tid of a Def or Jmp, then it describes the point in time *after* the execution of the Def or Jmp.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct AbstractIdentifier(FastCmpArc<AbstractIdentifierData>);

/// The data contained in an abstract identifier
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct AbstractIdentifierData {
    time: Tid,
    location: AbstractLocation,
}

impl AbstractIdentifier {
    /// create a new abstract identifier
    pub fn new(time: Tid, location: AbstractLocation) -> AbstractIdentifier {
        AbstractIdentifier(FastCmpArc(Arc::new(AbstractIdentifierData{
            time,
            location
        })))
    }
}

/// An abstract location describes how to find the value of a variable in memory at a given time.
///
/// It is defined recursively, where the root is always a register.
/// This way only locations that the local state knows about are representable.
/// It is also impossible to accidently describe circular references.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractLocation {
    Register(String, BitSize),
    Pointer(String, AbstractMemoryLocation),
}

impl AbstractLocation {
    /// Create an abstract location from a variable corresponding to a register.
    /// This function returns an error if the variable is not a physical register.
    pub fn from_var(variable: &Variable) -> Result<AbstractLocation, Error> {
        if variable.is_temp {
            return Err(anyhow!("Cannot create abstract location from temporary variables."));
        }
        Ok(AbstractLocation::Register(variable.name.clone(), variable.bitsize()?))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractMemoryLocation {
    Location {
        offset: isize,
        size: usize,
    },
    Pointer {
        offset: isize,
        size: usize,
        target: Box<AbstractMemoryLocation>
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_identifier() {
        unimplemented!()
    }
}
