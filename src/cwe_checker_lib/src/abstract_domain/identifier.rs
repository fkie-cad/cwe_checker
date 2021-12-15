use crate::intermediate_representation::*;
use crate::prelude::*;
use derive_more::Deref;
use std::sync::Arc;

/// An abstract identifier is used to identify an object or a value in an abstract state.
///
/// Since many program states can be represented by the same abstract state in data-flow analysis,
/// one sometimes needs a way to uniquely identify a variable or a memory object in all of the represented program states.
/// Abstract identifiers achieve this by identifying a *time*, i.e. a specific abstract state,
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
    /// Create a new abstract identifier.
    pub fn new(time: Tid, location: AbstractLocation) -> AbstractIdentifier {
        AbstractIdentifier(Arc::new(AbstractIdentifierData { time, location }))
    }

    /// Create a new abstract identifier where the abstract location is a register.
    /// Panics if the register is a temporary register.
    pub fn new_from_var(time: Tid, variable: &Variable) -> AbstractIdentifier {
        AbstractIdentifier(Arc::new(AbstractIdentifierData {
            time,
            location: AbstractLocation::from_var(variable).unwrap(),
        }))
    }

    /// Get the register associated to the abstract location.
    /// Panics if the abstract location is a memory location and not a register.
    pub fn unwrap_register(&self) -> &Variable {
        match &self.location {
            AbstractLocation::Register(var) => var,
            AbstractLocation::Pointer(_, _) => panic!("Abstract location is not a register."),
        }
    }

    /// Get the TID representing the time component of the abstract ID.
    pub fn get_tid(&self) -> &Tid {
        &self.time
    }

    /// Get the location component of the abstract ID
    pub fn get_location(&self) -> &AbstractLocation {
        &self.location
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
/// It is also impossible to accidentally describe circular references.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractLocation {
    /// The location is given by a register.
    Register(Variable),
    /// The location is in memory.
    /// One needs to follow the pointer in the given register
    /// and then follow the abstract memory location inside the pointed to memory object
    /// to find the actual memory location.
    Pointer(Variable, AbstractMemoryLocation),
}

impl std::fmt::Display for AbstractLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Register(var) => write!(formatter, "{}", var.name),
            Self::Pointer(var, location) => write!(formatter, "{}->{}", var.name, location),
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
        Ok(AbstractLocation::Register(variable.clone()))
    }

    /// Create an abstract location on the stack.
    /// The returned location describes the value of the given `size`
    /// at the given `offset` relative to the memory location that the `stack_register` is pointing to.
    pub fn from_stack_position(
        stack_register: &Variable,
        offset: i64,
        size: ByteSize,
    ) -> AbstractLocation {
        let stack_pos = AbstractMemoryLocation::Location { offset, size };
        AbstractLocation::Pointer(stack_register.clone(), stack_pos)
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
        offset: i64,
        /// The size in bytes of the value that the memory location points to.
        size: ByteSize,
    },
    /// A pointer which needs to be followed to get to the actual memory location
    Pointer {
        /// The offset inside the current memory object where the pointer can be found.
        offset: i64,
        /// The memory location inside the target of the pointer that this memory location points to.
        target: Box<AbstractMemoryLocation>,
    },
}

impl std::fmt::Display for AbstractMemoryLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Location { offset, .. } => write!(formatter, "({})", offset),
            Self::Pointer { offset, target } => write!(formatter, "({})->{}", offset, target),
        }
    }
}
