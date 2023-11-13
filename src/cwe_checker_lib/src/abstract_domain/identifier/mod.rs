use crate::intermediate_representation::*;
use crate::prelude::*;
use derive_more::Deref;
use std::sync::Arc;

mod location;
pub use location::AbstractLocation;
mod mem_location;
pub use mem_location::AbstractMemoryLocation;

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
/// Alternatively one can also add path hints to an identifier to further distinguish points in time in an execution trace.
/// Path hints are given as a possibly empty array of time identifiers.
/// To prevent infinitely long path hints, each time identifier is only allowed to appear at most once in the array.
/// The specific meaning of the path hints depends upon the use case.
///
/// An abstract identifier is given by a time identifier, a location identifier and a path hints array (containing time identifiers).
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
    path_hints: Vec<Tid>,
}

impl AbstractIdentifier {
    /// Create a new abstract identifier.
    pub fn new(time: Tid, location: AbstractLocation) -> AbstractIdentifier {
        AbstractIdentifier(Arc::new(AbstractIdentifierData {
            time,
            location,
            path_hints: Vec::new(),
        }))
    }

    /// Create a new abstract identifier where the abstract location is a register.
    /// Panics if the register is a temporary register.
    pub fn from_var(time: Tid, variable: &Variable) -> AbstractIdentifier {
        AbstractIdentifier(Arc::new(AbstractIdentifierData {
            time,
            location: AbstractLocation::from_var(variable).unwrap(),
            path_hints: Vec::new(),
        }))
    }

    /// Create an abstract identifier from a parameter argument.
    ///
    /// If the argument is a sub-register, then the created identifier contains the whole base register.
    pub fn from_arg(time: &Tid, arg: &Arg) -> AbstractIdentifier {
        let location_register = match arg {
            Arg::Register { expr, .. } | Arg::Stack { address: expr, .. } => {
                match &expr.input_vars()[..] {
                    [var] => *var,
                    _ => panic!("Malformed argument expression encountered"),
                }
            }
        };
        let location = match arg {
            Arg::Register { .. } => AbstractLocation::from_var(location_register).unwrap(),
            Arg::Stack { size, .. } => AbstractLocation::from_stack_position(
                location_register,
                arg.eval_stack_offset().unwrap().try_to_i64().unwrap(),
                *size,
            ),
        };
        AbstractIdentifier::new(time.clone(), location)
    }

    /// Create an abstract identifier from an address into global memory.
    pub fn from_global_address(time: &Tid, address: &Bitvector) -> AbstractIdentifier {
        AbstractIdentifier::new(time.clone(), AbstractLocation::from_global_address(address))
    }

    /// Create a new abstract identifier
    /// by pushing the given path hint to the array of path hints of `self`.
    /// Returns an error if the path hint is already contained in the path hints of `self`.
    pub fn with_path_hint(&self, path_hint: Tid) -> Result<Self, Error> {
        if self.path_hints.iter().any(|tid| *tid == path_hint) {
            Err(anyhow!("Path hint already contained."))
        } else {
            let mut new_id = self.clone();
            let inner = Arc::make_mut(&mut new_id.0);
            inner.path_hints.push(path_hint);
            Ok(new_id)
        }
    }

    /// Create a new abstract identifier by removing the last path hint from the path hint array of `self`.
    /// Return the new identifier together with the removed path hint (or none if `self` has no path hints).
    pub fn without_last_path_hint(&self) -> (Self, Option<Tid>) {
        let mut new_id = self.clone();
        let inner = Arc::make_mut(&mut new_id.0);
        let last_path_hint = inner.path_hints.pop();

        (new_id, last_path_hint)
    }

    /// Get the path hints array of `self`.
    pub fn get_path_hints(&self) -> &[Tid] {
        &self.path_hints
    }

    /// Get the register associated to the abstract location.
    /// Panics if the abstract location is not a register but a memory location.
    pub fn unwrap_register(&self) -> &Variable {
        match &self.location {
            AbstractLocation::Register(var) => var,
            AbstractLocation::GlobalAddress { .. }
            | AbstractLocation::GlobalPointer(_, _)
            | AbstractLocation::Pointer(_, _) => panic!("Abstract location is not a register."),
        }
    }

    /// Get the TID representing the time component of the abstract ID.
    pub fn get_tid(&self) -> &Tid {
        &self.time
    }

    /// Get the location component of the abstract ID.
    pub fn get_location(&self) -> &AbstractLocation {
        &self.location
    }

    /// Get the bytesize of the value represented by the abstract ID.
    pub fn bytesize(&self) -> ByteSize {
        self.location.bytesize()
    }
}

impl std::fmt::Display for AbstractIdentifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.path_hints.is_empty() {
            write!(formatter, "{} @ {}", self.0.time, self.0.location)
        } else {
            write!(formatter, "{}(", self.0.time)?;
            for hint in &self.0.path_hints {
                write!(formatter, "->{hint}",)?;
            }
            write!(formatter, ") @ {}", self.0.location)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::variable;

    impl AbstractIdentifier {
        /// Mock an abstract identifier with the given TID name and pointing to the value in the given register name.
        pub fn mock(
            tid: impl ToString,
            register: impl ToString,
            size_in_bytes: u64,
        ) -> AbstractIdentifier {
            AbstractIdentifier::new(
                Tid::new(tid.to_string()),
                AbstractLocation::from_var(&variable!(format!(
                    "{}:{}",
                    register.to_string(),
                    size_in_bytes
                )))
                .unwrap(),
            )
        }
    }

    #[test]
    fn test_constraint_enforcements() {
        // Test that no temporary registers are allowed as abstract locations.
        assert!(AbstractLocation::from_var(&Variable {
            name: "var".to_string(),
            size: ByteSize::new(8),
            is_temp: true,
        })
        .is_err());
        // Test uniqueness of TIDs in path hint array.
        let id = AbstractIdentifier::new(
            Tid::new("time_id"),
            AbstractLocation::from_var(&variable!("var:8")).unwrap(),
        );
        let id = id.with_path_hint(Tid::new("first_hint")).unwrap();
        let id = id.with_path_hint(Tid::new("second_hint")).unwrap();
        assert!(id.with_path_hint(Tid::new("first_hint")).is_err());
    }

    #[test]
    fn test_bytesize() {
        let location =
            AbstractLocation::from_stack_position(&variable!("RSP:8"), 10, ByteSize::new(4));
        let id = AbstractIdentifier::new(Tid::new("id"), location);
        assert_eq!(id.bytesize(), ByteSize::new(4));
    }
}
