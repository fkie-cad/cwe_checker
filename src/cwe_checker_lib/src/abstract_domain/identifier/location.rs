use super::AbstractMemoryLocation;
use crate::intermediate_representation::*;
use crate::prelude::*;

/// An abstract location describes how to find the value of a variable in memory at a given time.
///
/// It is defined recursively, where the root is either a register or a (constant) global address.
/// This way only locations that the local state knows about are representable.
/// It is also impossible to accidentally describe circular references.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum AbstractLocation {
    /// The location is given by a register.
    Register(Variable),
    /// The value itself is a constant address to global memory.
    /// Note that the `size` is the size of the pointer and not the size
    /// of the value residing at the specific address in global memory.
    GlobalAddress {
        /// The address in global memory.
        address: u64,
        /// The byte size of the address (not the pointed-to value!).
        size: ByteSize,
    },
    /// The location is in memory.
    /// One needs to follow the pointer in the given register
    /// and then follow the abstract memory location inside the pointed to memory object
    /// to find the actual memory location.
    Pointer(Variable, AbstractMemoryLocation),
    /// The location is in memory.
    /// One needs to follow the pointer located at the given global address
    /// and then follow the abstract memory location inside the pointed to memory object
    /// to find the actual memory location.
    GlobalPointer(u64, AbstractMemoryLocation),
}

impl std::fmt::Display for AbstractLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Register(var) => write!(formatter, "{}", var.name)?,
            Self::GlobalAddress { address, size: _ } => write!(formatter, "0x{address:x}")?,
            Self::Pointer(var, location) => write!(formatter, "{}{}", var.name, location)?,
            Self::GlobalPointer(address, location) => write!(formatter, "0x{address:x}{location}")?,
        };
        write!(formatter, ":i{}", self.bytesize().as_bit_length())
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

    /// Create an abstract location representing an address pointing to global memory.
    pub fn from_global_address(address: &Bitvector) -> AbstractLocation {
        let size = address.bytesize();
        let address = address
            .try_to_u64()
            .expect("Global address larger than 64 bits encountered.");
        AbstractLocation::GlobalAddress { address, size }
    }

    /// Add an offset to the abstract location.
    pub fn with_offset_addendum(self, addendum: i64) -> AbstractLocation {
        match self {
            Self::Register(_) => panic!("Cannot add an offset to a register abstract location"),
            Self::GlobalAddress { address, size } => Self::GlobalAddress {
                address: address + (addendum as u64),
                size,
            },
            Self::Pointer(var, mut location) => {
                location.add_offset(addendum);
                Self::Pointer(var, location)
            }
            Self::GlobalPointer(address, mut location) => {
                location.add_offset(addendum);
                Self::GlobalPointer(address, location)
            }
        }
    }

    /// Return the abstract location that one gets when dereferencing the pointer that `self` is pointing to.
    ///
    /// Panics if `self` is not pointer-sized.
    pub fn dereferenced(
        self,
        new_size: ByteSize,
        generic_pointer_size: ByteSize,
    ) -> AbstractLocation {
        match self {
            Self::Register(var) => Self::Pointer(
                var,
                AbstractMemoryLocation::Location {
                    offset: 0,
                    size: new_size,
                },
            ),
            Self::GlobalAddress { address, size } => {
                assert_eq!(
                    size, generic_pointer_size,
                    "Cannot dereference an abstract memory location that is not pointer-sized."
                );
                Self::GlobalPointer(
                    address,
                    AbstractMemoryLocation::Location {
                        offset: 0,
                        size: new_size,
                    },
                )
            }
            Self::GlobalPointer(address, mut location) => {
                location.dereference(new_size, generic_pointer_size);
                Self::GlobalPointer(address, location)
            }
            Self::Pointer(var, mut location) => {
                location.dereference(new_size, generic_pointer_size);
                Self::Pointer(var.clone(), location)
            }
        }
    }

    /// Get the bytesize of the value represented by the abstract location.
    pub fn bytesize(&self) -> ByteSize {
        match self {
            Self::Register(var) => var.size,
            Self::GlobalAddress { size, .. } => *size,
            Self::Pointer(_, mem_location) | Self::GlobalPointer(_, mem_location) => {
                mem_location.bytesize()
            }
        }
    }

    /// Get the recursion depth of the abstract location,
    /// i.e. how many times one has to dereference a pointer until reaching the actual location.
    pub fn recursion_depth(&self) -> u64 {
        match self {
            Self::Register(_) => 0,
            Self::GlobalAddress { .. } => 1,
            Self::Pointer(_, mem_location) | Self::GlobalPointer(_, mem_location) => {
                1 + mem_location.recursion_depth()
            }
        }
    }

    /// Extend the location string by adding further derefence operations to it according to the given extension.
    pub fn extend(&mut self, extension: AbstractMemoryLocation, generic_pointer_size: ByteSize) {
        match self {
            Self::Pointer(_, location) | Self::GlobalPointer(_, location) => {
                location.extend(extension, generic_pointer_size);
            }
            Self::GlobalAddress { address, size } => {
                assert_eq!(*size, generic_pointer_size);
                *self = Self::GlobalPointer(*address, extension);
            }
            Self::Register(var) => {
                assert_eq!(var.size, generic_pointer_size);
                *self = Self::Pointer(var.clone(), extension);
            }
        }
    }

    /// Get the abstract location representing the pointer pointing to the memory object
    /// that contains the location represented by `self`
    /// together with the offset that one has to add to the pointer to get the location of self.
    ///
    /// Returns an error if the abstract location contains no dereference operation
    /// (e.g. if `self` represents a register value).
    pub fn get_parent_location(
        &self,
        generic_pointer_size: ByteSize,
    ) -> Result<(AbstractLocation, i64), Error> {
        match self {
            AbstractLocation::GlobalAddress { .. } | AbstractLocation::Register(_) => {
                Err(anyhow!("Root location without a parent."))
            }
            AbstractLocation::GlobalPointer(address, location) => {
                match location.get_parent_location(generic_pointer_size) {
                    Ok((inner_parent_location, innermost_offset)) => Ok((
                        Self::GlobalPointer(*address, inner_parent_location),
                        innermost_offset,
                    )),
                    Err(innermost_offset) => Ok((
                        Self::GlobalAddress {
                            address: *address,
                            size: generic_pointer_size,
                        },
                        innermost_offset,
                    )),
                }
            }
            AbstractLocation::Pointer(var, location) => {
                match location.get_parent_location(generic_pointer_size) {
                    Ok((inner_parent_location, innermost_offset)) => Ok((
                        Self::Pointer(var.clone(), inner_parent_location),
                        innermost_offset,
                    )),
                    Err(innermost_offset) => Ok((Self::Register(var.clone()), innermost_offset)),
                }
            }
        }
    }

    /// Get a list of all (recursive) parent locations.
    /// The list is sorted by recursion depth, starting with the root location.
    pub fn get_all_parent_locations(
        &self,
        generic_pointer_size: ByteSize,
    ) -> Vec<AbstractLocation> {
        match self {
            AbstractLocation::GlobalAddress { .. } | AbstractLocation::Register(_) => Vec::new(),
            AbstractLocation::GlobalPointer(_, _) | AbstractLocation::Pointer(_, _) => {
                let (parent, _) = self.get_parent_location(generic_pointer_size).unwrap();
                let mut all_parents = parent.get_all_parent_locations(generic_pointer_size);
                all_parents.push(parent);
                all_parents
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::variable;

    impl AbstractLocation {
        /// Mock an abstract location with a variable as root.
        pub fn mock(
            root_var: &str,
            offsets: &[i64],
            size: impl Into<ByteSize>,
        ) -> AbstractLocation {
            let var = variable!(root_var);
            match offsets {
                [] => {
                    assert_eq!(var.size, size.into());
                    AbstractLocation::Register(var)
                }
                _ => AbstractLocation::Pointer(var, AbstractMemoryLocation::mock(offsets, size)),
            }
        }
        /// Mock an abstract location with a global address as root.
        pub fn mock_global(
            root_address: u64,
            offsets: &[i64],
            size: impl Into<ByteSize>,
        ) -> AbstractLocation {
            match offsets {
                [] => AbstractLocation::GlobalAddress {
                    address: root_address,
                    size: size.into(),
                },
                _ => AbstractLocation::GlobalPointer(
                    root_address,
                    AbstractMemoryLocation::mock(offsets, size),
                ),
            }
        }
    }

    #[test]
    fn test_from_variants() {
        let loc = AbstractLocation::from_var(&variable!("RAX:8")).unwrap();
        assert_eq!(&format!("{loc}"), "RAX:i64");
        let loc = AbstractLocation::from_global_address(&Bitvector::from_u64(32));
        assert_eq!(
            loc,
            AbstractLocation::GlobalAddress {
                address: 32,
                size: ByteSize::new(8)
            }
        );
        let loc = AbstractLocation::from_stack_position(&variable!("RSP:8"), 16, ByteSize::new(8));
        assert_eq!(loc, AbstractLocation::mock("RSP:8", &[16], 8));
    }

    #[test]
    fn test_with_offset_addendum() {
        let loc = AbstractLocation::mock("RAX:8", &[1, 2, 3], 4).with_offset_addendum(12);
        assert_eq!(loc, AbstractLocation::mock("RAX:8", &[1, 2, 15], 4));
    }

    #[test]
    fn test_dereferenced() {
        let loc = AbstractLocation::mock("RAX:8", &[], 8)
            .dereferenced(ByteSize::new(4), ByteSize::new(8));
        assert_eq!(loc, AbstractLocation::mock("RAX:8", &[0], 4));
    }

    #[test]
    fn test_recursion_depth() {
        let loc = AbstractLocation::mock("RAX:8", &[1, 2, 3], 4);
        assert_eq!(loc.recursion_depth(), 3);
    }

    #[test]
    fn test_extend() {
        let mut loc = AbstractLocation::mock("RAX:8", &[1, 2, 3], 4);
        let extension = AbstractMemoryLocation::mock(&[4, 5, 6], 1);
        loc.extend(extension, ByteSize::new(4));
        assert_eq!(loc, AbstractLocation::mock("RAX:8", &[1, 2, 3, 4, 5, 6], 1));
    }

    #[test]
    fn test_get_parent_location() {
        let loc = AbstractLocation::mock("RAX:8", &[1], 4);
        let (parent, last_offset) = loc.get_parent_location(ByteSize::new(8)).unwrap();
        assert_eq!(parent, AbstractLocation::mock("RAX:8", &[], 8));
        assert_eq!(last_offset, 1);
        let loc = AbstractLocation::mock("RAX:8", &[1, 2, 3], 4);
        let (parent, last_offset) = loc.get_parent_location(ByteSize::new(8)).unwrap();
        assert_eq!(parent, AbstractLocation::mock("RAX:8", &[1, 2], 8));
        assert_eq!(last_offset, 3);
    }
}
