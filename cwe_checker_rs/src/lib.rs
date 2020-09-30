/*!
# cwe_checker_rs

Parts of the cwe_checker that are written in Rust.
*/

#[macro_use]
extern crate ocaml;

pub mod abstract_domain;
pub mod analysis;
pub mod bil;
pub mod ffi;
pub mod intermediate_representation;
pub mod pcode;
pub mod term;
pub mod utils;

mod prelude {
    pub use apint::Width;
    pub use serde::{Deserialize, Serialize};

    pub use crate::bil::{BitSize, Bitvector};
    pub use crate::intermediate_representation::{Term, Tid};
    pub use anyhow::{anyhow, Error};
}
