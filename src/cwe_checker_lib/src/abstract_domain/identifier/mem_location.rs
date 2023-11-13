use crate::prelude::*;

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

impl AbstractMemoryLocation {
    /// Get the abstract memory location representing the pointer pointing to the memory object
    /// that contains the location represented by `self`
    /// together with the offset that one has to add to the pointer to get the location of self.
    ///
    /// If `self` is a location (and not a pointer), return the offset in the location instead.
    pub fn get_parent_location(
        &self,
        generic_pointer_size: ByteSize,
    ) -> Result<(AbstractMemoryLocation, i64), i64> {
        match self {
            Self::Location { offset, size } => Err(*offset),
            Self::Pointer { offset, target } => {
                match target.get_parent_location(generic_pointer_size) {
                    Ok((inner_parent, innermost_offset)) => Ok((
                        Self::Pointer {
                            offset: *offset,
                            target: Box::new(inner_parent),
                        },
                        innermost_offset,
                    )),
                    Err(inner_offset) => Ok((
                        Self::Location {
                            offset: *offset,
                            size: generic_pointer_size,
                        },
                        inner_offset,
                    )),
                }
            }
        }
    }

    /// Add an offset to a memory location.
    pub fn add_offset(&mut self, addendum: i64) {
        match self {
            Self::Location { offset, .. } => *offset += addendum,
            Self::Pointer { target, .. } => target.add_offset(addendum),
        }
    }

    /// Dereference the pointer that `self` is pointing to.
    ///
    /// Panics if the old value of `self` is not pointer-sized.
    pub fn dereference(&mut self, new_size: ByteSize, generic_pointer_size: ByteSize) {
        match self {
            Self::Pointer { target, .. } => target.dereference(new_size, generic_pointer_size),
            Self::Location { offset, size } => {
                assert_eq!(
                    *size, generic_pointer_size,
                    "Cannot dereference an abstract memory location that is not pointer-sized."
                );
                *self = Self::Pointer {
                    offset: *offset,
                    target: Box::new(Self::Location {
                        offset: 0,
                        size: new_size,
                    }),
                }
            }
        };
    }

    /// Extend the location string by adding further derefence operations to it according to the given extension.
    pub fn extend(&mut self, extension: AbstractMemoryLocation, generic_pointer_size: ByteSize) {
        match self {
            Self::Location { offset, size } => {
                assert_eq!(*size, generic_pointer_size);
                *self = Self::Pointer {
                    offset: *offset,
                    target: Box::new(extension),
                };
            }
            Self::Pointer { target, .. } => target.extend(extension, generic_pointer_size),
        }
    }

    /// Get the bytesize of the value represented by the abstract memory location.
    pub fn bytesize(&self) -> ByteSize {
        match self {
            Self::Location { size, .. } => *size,
            Self::Pointer { target, .. } => target.bytesize(),
        }
    }

    /// Get the recursion depth of the abstract memory location,
    /// i.e. how many times one has to dereference a pointer until reaching the actual location.
    pub fn recursion_depth(&self) -> u64 {
        match self {
            Self::Location { .. } => 0,
            Self::Pointer { target, .. } => 1 + target.recursion_depth(),
        }
    }
}

impl std::fmt::Display for AbstractMemoryLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Location { offset, .. } => write!(formatter, "({offset})"),
            Self::Pointer { offset, target } => write!(formatter, "({offset})->{target}"),
        }
    }
}
