use crate::intermediate_representation::*;
use crate::prelude::*;
use derive_more::Deref;
use std::sync::Arc;

/// An abstract identifier is used to identify an object or a value in an abstract state.
///
/// Since many program states can be represented by the same abstract state in data-flow analysis,
/// one sometimes needs a way to uniquely identify a variable or a memory object in all of the represented program states.
/// Abstract identifier achieve this by identifying a *time*, i.e. a specific abstract state,
/// and a *location*, i.e. a recipe for abstracting a concrete value from any concrete state that is represented by the abstract state.
/// The value in question then serves as the identifier.
/// For example, a pointer may uniquely determine the memory object it is pointing to.
/// Or a value may represent the value of a variable at a certain time,
/// whereas the value of the variable in the current state is given as an offset to the value at the identified time.
///
/// Since program points may be visited several times during an execution trace (e.g. in loops),
/// the *time* component of an abstract identifier may not actually determine an unique point in time of an execution trace.
/// In this case the meaning of an abstract identifier depends upon its use case.
/// E.g. it may represent the union of all values at the specific *location* for each time the program point is visited during an execution trace
/// or it may only represent the value at the last time the program point was visited.
///
/// An abstract identifier is given by a time identifier and a location identifier.
///
/// For the location identifier see `AbstractLocation`.
/// The time identifier is given by a `Tid`.
/// If it is the `Tid` of a basic block, then it describes the point in time *before* execution of the first instruction in the block.
/// If it is the `Tid` of a `Def` or `Jmp`, then it describes the point in time *after* the execution of the `Def` or `Jmp`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord, Deref)]
#[deref(forward)]
pub struct AbstractIdentifier(Arc<AbstractIdentifierData>);

/// The data contained in an abstract identifier
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct AbstractIdentifierData {
    time: Tid,
    location: AbstractLocation,
}

impl AbstractIdentifier {
    /// create a new abstract identifier
    pub fn new(time: Tid, location: AbstractLocation) -> AbstractIdentifier {
        AbstractIdentifier(Arc::new(AbstractIdentifierData { time, location }))
    }
}

impl std::fmt::Display for AbstractIdentifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{} @ {}", self.0.time, self.0.location)
    }
}

/// An abstract location describes how to find the value of a variable in memory at a given time.
///
/// It is defined recursively, where the root is always a register.
/// This way only locations that the local state knows about are representable.
/// It is also impossible to accidently describe circular references.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractLocation {
    /// The location is given by a register with the given name and byte size.
    Register(String, ByteSize),
    /// The location is in memory.
    /// One needs to follow the pointer in the register with the given name (as `String`)
    /// and then follow the abstract memory location inside the pointed to memory object
    /// to find the actual memory location.
    Pointer(String, AbstractMemoryLocation),
}

impl std::fmt::Display for AbstractLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Register(name, _size) => write!(formatter, "{}", name),
            Self::Pointer(reg_name, location) => write!(formatter, "{}->{}", reg_name, location),
        }
    }
}

impl AbstractLocation {
    /// Create an abstract location from a variable corresponding to a register.
    /// This function returns an error if the variable is not a physical register.
    pub fn from_var(variable: &Variable) -> Result<AbstractLocation, Error> {
        if variable.is_temp {
            return Err(anyhow!(
                "Cannot create abstract location from temporary variables."
            ));
        }
        Ok(AbstractLocation::Register(
            variable.name.clone(),
            variable.size,
        ))
    }

    /// Creates an abstract location from a stack position.
    /// It creates an abstract memory location using the stack pointer
    /// and an offset.
    pub fn from_stack(
        stack_pointer_register: &Variable,
        size: &ByteSize,
        offset: &i64,
    ) -> Result<AbstractLocation, Error> {
        Ok(AbstractLocation::Pointer(
            stack_pointer_register.name.clone(),
            AbstractMemoryLocation::Location {
                offset: offset.clone() as isize,
                size: size.as_bit_length(),
            },
        ))
    }
}

/// An abstract memory location is either an offset from the given location, where the actual value can be found,
/// or an offset to a pointer to another memory location,
/// where the value can be found by (recursively) following the embedded `target` memory location.
///
/// The offset and size variables are given in bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractMemoryLocation {
    /// A location inside the current memory object.
    Location {
        /// The offset with respect to the zero offset of the memory object where the value can be found.
        offset: isize,
        /// The size in bytes of the value that the memory location points to.
        size: usize,
    },
    /// A pointer which needs to be followed to get to the actual memory location
    Pointer {
        /// The offset inside the current memory object where the pointer can be found.
        offset: isize,
        /// The size in bytes of the pointer.
        size: usize,
        /// The memory location inside the target of the pointer that this memory location points to.
        target: Box<AbstractMemoryLocation>,
    },
}

impl std::fmt::Display for AbstractMemoryLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Location { offset, .. } => write!(formatter, "({})", offset),
            Self::Pointer {
                offset,
                size: _,
                target,
            } => write!(formatter, "({})->{}", offset, target),
        }
    }
}
