//! Tracking of taint in registers.

use crate::abstract_domain::{DomainMap, UnionMergeStrategy};
use crate::intermediate_representation::Variable;

use super::Taint;

/// Represents our knowledge about taint in registers at a particular point in
/// the program.
pub type RegisterTaint = DomainMap<Variable, Taint, UnionMergeStrategy>;
