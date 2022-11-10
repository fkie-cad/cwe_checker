//! Types to describe Ghidra P-Code
//! and functions to translate it to the internally used intermediate representation.
//!
//! The types in this module are not an exact representation of P-Code,
//! as some preprocessing is already done in the P-Code-Extractor plugin.
//!
//! The contents of this module are only used for the initial translation of P-Code into the internally used IR.
//! For everything else the [`intermediate_representation`](crate::intermediate_representation) should be used directly.

mod expressions;
pub use expressions::*;
mod term;
pub use term::*;
mod subregister_substitution;
