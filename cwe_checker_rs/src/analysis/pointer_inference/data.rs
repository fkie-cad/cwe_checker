use crate::analysis::abstract_domain::*;
use crate::bil::BitSize;
use crate::term::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::BTreeMap;

/// An abstract location describes how to find the value of a variable in memory at a given time.
///
/// It is defined recursively, where the root is always a register.
/// This way only locations that the local state knows about are representable.
/// It is also impossible to accidently describe circular references.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
enum AbstractLocation {
    Register(String),
    Memory {
        location: Box<AbstractLocation>,
        offset: isize,
        size: usize,
    },
}

/// An abstract identifier is given by a time identifier and a location identifier.
///
/// For the location identifier see `AbstractLocation`.
/// The time identifier is given by a `Tid`.
/// If it is the Tid of a basic block, then it describes the point in time *before* execution of the first instruction in the block.
/// If it is the Tid of a Def or Jmp, then it describes the point in time *after* the execution of the Def or Jmp.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct AbstractIdentifier {
    time: Tid,
    location: AbstractLocation,
}

/// An abstract value representing either a pointer or a constant value.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Data {
    Top(BitSize),
    Pointer(PointerDomain),
    Value(BitvectorDomain),
    Bottom(BitSize),
}

/// An abstract value representing a pointer given as a map from an abstract identifier
/// to the offset in the pointed to object.
///
/// The map should never be empty. If the map contains more than one key,
/// it indicates that the pointer may point to any of the contained objects.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PointerDomain(BTreeMap< Arc<AbstractIdentifier>, BitvectorDomain >);

impl PointerDomain {
    /// get the bitsize of the pointer
    pub fn bitsize(&self) -> BitSize {
        let some_elem = self.0.values().next().unwrap();
        some_elem.bitsize()
    }

    pub fn merge(&self, other: &PointerDomain) -> PointerDomain {
        let mut merged_map = self.0.clone();
        for (location, offset) in other.0.iter() {
            if merged_map.contains_key(location) {
                merged_map.insert(location.clone(), merged_map[location].merge(offset));
            } else {
                merged_map.insert(location.clone(), offset.clone());
            }
        }
        PointerDomain(merged_map)
    }
}

impl ValueDomain for Data {
    fn bitsize(&self) -> BitSize {
        use Data::*;
        match self {
            Top(size) | Bottom(size) => *size,
            Pointer(pointer) => pointer.bitsize(),
            Value(bitvec) => bitvec.bitsize(),
        }
    }

    fn new_top(bitsize: BitSize) -> Data {
        Data::Top(bitsize)
    }
}

impl AbstractDomain for Data {
    fn top(&self) -> Self {
        Data::Top(self.bitsize())
    }

    fn merge(&self, other: &Self) -> Self {
        use Data::*;
        match (self, other) {
            (Top(bitsize), _) | (_, Top(bitsize)) => Top(*bitsize),
            (Pointer(pointer1), Pointer(pointer2)) => Pointer(pointer1.merge(pointer2)),
            (Value(val1), Value(val2)) => Value(val1.merge(val2)),
            (Bottom(_), not_bottom) | (not_bottom, Bottom(_)) => not_bottom.clone(),
            (Pointer(_), Value(_)) | (Value(_), Pointer(_)) => Top(self.bitsize()),
        }
    }
}
