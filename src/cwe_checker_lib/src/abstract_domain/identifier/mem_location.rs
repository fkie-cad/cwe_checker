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
            Self::Location { offset, .. } => Err(*offset),
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

    /// Add an offset to the root location of the memory location.
    pub fn add_offset_at_root(&mut self, addendum: i64) {
        match self {
            Self::Location { offset, .. } | Self::Pointer { offset, .. } => *offset += addendum,
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
            Self::Location { offset, .. } => write!(formatter, "[0x{offset:x}]"),
            Self::Pointer { offset, target } => write!(formatter, "[0x{offset:x}]{target}"),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl AbstractMemoryLocation {
        /// Mock a memory location with a given sequence of offsets.
        /// The first element in the sequence is the root offset.
        pub fn mock(offsets: &[i64], size: impl Into<ByteSize>) -> AbstractMemoryLocation {
            match offsets {
                [] => panic!(),
                [offset] => AbstractMemoryLocation::Location {
                    offset: *offset,
                    size: size.into(),
                },
                [offset, tail @ ..] => AbstractMemoryLocation::Pointer {
                    offset: *offset,
                    target: Box::new(AbstractMemoryLocation::mock(tail, size)),
                },
            }
        }
    }

    #[test]
    fn test_mock() {
        let loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        assert_eq!(&format!("{loc}"), "[0x1][0x2][0x3]");
    }

    #[test]
    fn test_get_parent_location() {
        let loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        let (parent_loc, last_offset) = loc.get_parent_location(ByteSize::new(8)).unwrap();
        assert_eq!(parent_loc, AbstractMemoryLocation::mock(&[1, 2], 8));
        assert_eq!(last_offset, 3);
        let loc = AbstractMemoryLocation::mock(&[1], 4);
        assert!(loc.get_parent_location(ByteSize::new(8)).is_err());
    }

    #[test]
    fn test_offset_addendums() {
        let mut loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        loc.add_offset(6);
        assert_eq!(&loc, &AbstractMemoryLocation::mock(&[1, 2, 9], 4));
        loc.add_offset_at_root(-5);
        assert_eq!(&loc, &AbstractMemoryLocation::mock(&[-4, 2, 9], 4));
    }

    #[test]
    fn test_dereference() {
        let mut loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        loc.dereference(ByteSize::new(8), ByteSize::new(4));
        assert_eq!(loc, AbstractMemoryLocation::mock(&[1, 2, 3, 0], 8))
    }

    #[test]
    fn test_extend() {
        let mut loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        let extension = AbstractMemoryLocation::mock(&[4, 5, 6], 1);
        loc.extend(extension, ByteSize::new(4));
        assert_eq!(loc, AbstractMemoryLocation::mock(&[1, 2, 3, 4, 5, 6], 1));
    }

    #[test]
    fn test_recursion_depth() {
        let loc = AbstractMemoryLocation::mock(&[1, 2, 3], 4);
        assert_eq!(loc.recursion_depth(), 2);
        let loc = AbstractMemoryLocation::mock(&[1], 4);
        assert_eq!(loc.recursion_depth(), 0);
    }
}
