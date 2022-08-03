use crate::{abstract_domain::AbstractDomain, prelude::*};
use std::fmt::Display;

/// Access flags to track different kind of access/usage patterns of a variable.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct AccessPattern {
    /// The variable was used in the computation of a pointer that was dereferenced for reading a value.
    dereferenced: bool,
    /// The variable was accessed to compute some nontrivial value
    /// or the value was stored in some location.
    read: bool,
    /// The variable was used in the computation of a pointer that was dereferenced for writing a value.
    mutably_dereferenced: bool,
}

impl AccessPattern {
    /// Generate a new `AccessPattern` object with none of the access flags set.
    pub fn new() -> Self {
        Self {
            dereferenced: false,
            read: false,
            mutably_dereferenced: false,
        }
    }

    /// Generate a new `AccessPattern` object with all access flags set to true (to model unknown access).
    pub fn new_unknown_access() -> Self {
        Self {
            dereferenced: true,
            read: true,
            mutably_dereferenced: true,
        }
    }

    /// Set the access flag for read access and return `self`.
    pub fn with_read_flag(mut self) -> Self {
        self.read = true;
        self
    }

    /// Set the access flag for immutable pointer dereference and return `self`.
    pub fn with_dereference_flag(mut self) -> Self {
        self.dereferenced = true;
        self
    }

    /// Set the access flag for pointer dereference with write access to the pointer target and return `self`.
    pub fn with_mutably_dereferenced_flag(mut self) -> Self {
        self.mutably_dereferenced = true;
        self
    }

    /// Set the access flag for immutable pointer dereference.
    pub fn set_dereference_flag(&mut self) {
        self.dereferenced = true;
    }

    /// Set the access flag for read access.
    pub fn set_read_flag(&mut self) {
        self.read = true;
    }

    /// Set the access flag for pointer dereference (with write access to the target of the pointer).
    pub fn set_mutably_dereferenced_flag(&mut self) {
        self.mutably_dereferenced = true;
    }

    /// Set all access flags to indicate that any kind of access to the variable may have occured.
    pub fn set_unknown_access_flags(&mut self) {
        self.read = true;
        self.dereferenced = true;
        self.mutably_dereferenced = true;
    }

    /// Returns true if any of the access flags is set.
    pub fn is_accessed(&self) -> bool {
        self.read || self.dereferenced || self.mutably_dereferenced
    }

    /// Returns true if the dereferenced or mutably dereferenced access flag is set.
    pub fn is_dereferenced(&self) -> bool {
        self.dereferenced || self.mutably_dereferenced
    }

    /// Returns true if the mutably dereferenced access flag is set.
    pub fn is_mutably_dereferenced(&self) -> bool {
        self.mutably_dereferenced
    }
}

impl Default for AccessPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractDomain for AccessPattern {
    /// An access flag in the merged `AccessPattern` object is set
    /// if it is set in at least one of the input objects.
    fn merge(&self, other: &Self) -> Self {
        AccessPattern {
            dereferenced: self.dereferenced || other.dereferenced,
            read: self.read || other.read,
            mutably_dereferenced: self.mutably_dereferenced || other.mutably_dereferenced,
        }
    }

    /// Returns true if all of the access flags are set.
    fn is_top(&self) -> bool {
        self.read && self.dereferenced && self.mutably_dereferenced
    }
}

impl Display for AccessPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.read {
            write!(f, "r")?;
        } else {
            write!(f, "-")?;
        }
        if self.dereferenced {
            write!(f, "d")?;
        } else {
            write!(f, "-")?;
        }
        if self.mutably_dereferenced {
            write!(f, "w")?;
        } else {
            write!(f, "-")?;
        }
        Ok(())
    }
}
