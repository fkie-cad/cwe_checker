//! This module contains the BricksDomain and BrickDomain.
//!
//! The BricksDomain contains a sorted list of normalized BrickDomains.
//! It represents the composition of a string through sub sequences.
//! When a string is assigned to the BricksDomain, it is defined as a single sequence bricks
//! which occurs at least and at most one time which is represented by a min and max value in the
//! BrickDomain. e.g. "cwe" => \[\[{"cwe"}\]^{1,1}\]
//!
//! If two string are concatenated, their brick sequences are concatenated.
//! e.g. B1 = \[\[{"a"}\]^{1,1}\], B2 = \[\[{"b"}\]^{1,1}\] => B_new = \[\[{"a"}\]^{1,1}, \[{"b"}\]^{1,1}\]
//!
//! A set of strings can be built from multiple configurations of bricks
//! e.g. \[{"abc"}\]^{1,1} <=> \[{"a"}\]^{1,1}\[{"b"}\]^{1,1}\[{"c"}\]^{1,1}
//!
//! Introducing a normalized form \[T\]^{1,1} or \[T\]^{0, max>0}
//! will keep string representations unambiguous.
//!
//! Widening is applied for merges, so that the domains do not become too big.
//! Certain thresholds are defined which cause the domains to be widened if exceeded.
//! These thresholds are:
//!  - the *interval threshold* which overapproximates the number of times string sequences can occur in a brick.
//!  - the *sequence threshold* which  overapproximates the number of string sequences in a brick by forcing a *Top* value.
//!  - the *length threshold* which  overapproximates the number of bricks in the BricksDomain and forces a *Top* value.

use std::{collections::BTreeSet, fmt};

use super::{AbstractDomain, DomainInsertion, HasTop};
use crate::prelude::*;
use std::fmt::Debug;

mod brick;
use brick::Brick;

mod widening;

/// The BricksDomain contains a sorted list of single normalized BrickDomains.
/// It represents the composition of a string through sub sequences.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub enum BricksDomain {
    /// The *Top* value represents an invalid sequence.
    Top,
    /// This values represents a sequence of string subsequences.
    Value(Vec<BrickDomain>),
}

impl BricksDomain {
    /// A set of strings can be built from multiple configurations of bricks
    /// e.g. \[{abc}\]^{1,1} <=> \[{a}\]^{1,1}\[{b}\]^{1,1}\[{c}\]^{1,1}
    ///
    /// Introducing a normalized form \[T\]^{1,1} or \[T\]^{0, max>0}
    /// will keep string representations unambiguous.
    ///
    /// Normalizing can be seen as some kind of fixpoint for a set of 5 rules that are applied
    /// to the list of bricks until the state stays unchanged:
    /// 1. **remove** bricks of the form \[{}\]^{0,0} empty string
    /// 2. **merge** successive bricks with the same indices max = 1, min = 1, in a new single brick.
    ///    The new string set is the concatenation of the former two. e.g. B0 = \[{a,cd}\]^{1,1}
    ///    and B1 = \[{b,ef}\]^{1,1} become B_new = \[{ab, aef, cdb, cdef}\]^{1,1}.
    /// 3. **transform** a brick in which the number of applications is constant (min = max) into one in which
    ///    min = max = 1. e.g. B = \[{a,b}\]^{2,2} => B_new = \[{aa, ab, ba, bb}\]^{1,1}.
    /// 4. **merge** two successive bricks in which the set of strings is the same. e.g. B1 = \[S\]^{m1, M1}
    ///    and B2 = \[S\]^{m2, M2} => B_new = \[S\]^{m1+m2, M1+M2}
    /// 5. **break** a single brick with min >= 1 and max != min into two simpler bricks where B = \[S\]^{min,max} =>
    ///    B1 = \[S^min\]^{1,1}, B2 = \[S\]^{0, max-min}.
    ///    e.g. B = \[{a}\]^{2,5} => B1 = \[{aa}\]^{1,1}, B2 = \[{a}\]^{0,3}
    ///
    /// Since normalization is rather expensive w.r.t. runtime and since it could entail a precision loss,
    /// it is only computed after a merge or widening operation.
    pub fn normalize(&self) -> Self {
        let mut normalized = self.unwrap_value();
        // A second vector to do lookups and to iterate over the values.
        let mut lookup = self.unwrap_value();
        let mut unchanged = false;
        while !unchanged {
            for (index, brick_domain) in lookup.iter().enumerate() {
                // Ignore Top value bricks.
                if brick_domain.is_top() {
                    continue;
                }

                // Get the current brick for checks .
                let current_brick = brick_domain.unwrap_value();

                // --Step 1-- Check whether the brick contains the empty string only.
                // If so, remove the brick from the list.
                if current_brick.is_empty_string() {
                    normalized.remove(index);
                    break;
                }

                // --Step 3-- Check whether the lower and upper bound are greater or equal than 1.
                // If so, create all permutations of the size of min=max and set them to 1.
                if current_brick.get_min() == current_brick.get_max() && current_brick.get_min() > 1
                {
                    let transformed_brick = current_brick
                        .transform_brick_with_min_max_equal(current_brick.get_min() as usize);
                    normalized[index] = BrickDomain::Value(transformed_brick);
                    break;
                }

                // --Step 5-- Check whether min >= 1 and max > min.
                // If so, break the brick into simpler bricks.
                if current_brick.get_min() >= 1 && current_brick.get_max() > current_brick.get_min()
                {
                    let (new_brick1, new_brick2) =
                        current_brick.break_single_brick_into_simpler_bricks();
                    normalized[index] = BrickDomain::Value(new_brick1);
                    normalized.insert(index + 1, BrickDomain::Value(new_brick2));
                    break;
                }

                // Check whether bricks can be merged.
                if let Some(next_brick_domain) = lookup.get(index + 1) {
                    if !next_brick_domain.is_top() {
                        let next_brick = next_brick_domain.unwrap_value();
                        // --Step 2-- Check whether two successive bricks are bound by one in min and max.
                        // If so, merge them by taking the cartesian product of the sequences.
                        if (
                            current_brick.get_min(),
                            current_brick.get_max(),
                            next_brick.get_min(),
                            next_brick.get_max(),
                        ) == (1, 1, 1, 1)
                        {
                            let merged_brick =
                                current_brick.merge_bricks_with_bound_one(next_brick);
                            normalized[index] = BrickDomain::Value(merged_brick);
                            normalized.remove(index + 1);
                            break;
                        }
                        // --Step 4-- Check whether two successive bricks have equal content.
                        // If so, merge them with the same content and add their min and max values together.
                        else if current_brick.get_sequence() == next_brick.get_sequence() {
                            let merged_brick =
                                current_brick.merge_bricks_with_equal_content(next_brick);
                            normalized[index] = BrickDomain::Value(merged_brick);
                            normalized.remove(index + 1);
                            break;
                        }
                    }
                }
            }

            if lookup == normalized {
                unchanged = true;
            } else {
                lookup = normalized.clone();
            }
        }

        BricksDomain::Value(normalized)
    }

    /// Before merging two BrickDomain lists, the shorter one has to be padded
    /// with empty string bricks. To achieve higher positional
    /// correspondence, empty string bricks will be added in a way that
    /// equal bricks have the same indices in both lists.
    fn pad_list(&self, other: &BricksDomain) -> Self {
        let mut short_list = self.unwrap_value();
        let long_list = other.unwrap_value();
        let mut new_list: Vec<BrickDomain> = Vec::new();
        let len_diff = long_list.len() - short_list.len();

        let mut empty_bricks_added = 0;

        for i in 0..long_list.len() {
            if empty_bricks_added >= len_diff {
                new_list.push(short_list.get(0).unwrap().clone());
                short_list.remove(0);
            } else if short_list.is_empty()
                || short_list.get(0).unwrap() != long_list.get(i).unwrap()
            {
                new_list.push(BrickDomain::get_empty_brick_domain());
                empty_bricks_added += 1;
            } else {
                new_list.push(short_list.get(0).unwrap().clone());
                short_list.remove(0);
            }
        }

        BricksDomain::Value(new_list)
    }

    /// Unwraps a list of BrickDomains and panic if it's *Top*
    fn unwrap_value(&self) -> Vec<BrickDomain> {
        match self {
            BricksDomain::Value(bricks) => bricks.clone(),
            _ => panic!("Unexpected Brick Domain type."),
        }
    }
}

impl fmt::Display for BricksDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BricksDomain::Top => write!(f, "Top"),
            BricksDomain::Value(brick_domains) => {
                write!(f, "Bricks: ")?;
                for brick_domain in brick_domains.iter() {
                    write!(f, "{brick_domain} ")?;
                }

                Ok(())
            }
        }
    }
}

impl DomainInsertion for BricksDomain {
    /// Appends new bricks to the current BricksDomain.
    /// Used to insert format specifier in sprintf calls and for strcat call.
    fn append_string_domain(&self, string_domain: &Self) -> Self {
        match self {
            BricksDomain::Top => match string_domain {
                BricksDomain::Top => BricksDomain::Top,
                BricksDomain::Value(bricks) => {
                    let mut new_bricks = vec![BrickDomain::Top];
                    new_bricks.append(&mut bricks.clone());
                    BricksDomain::Value(new_bricks)
                }
            },
            BricksDomain::Value(bricks) => match string_domain {
                BricksDomain::Top => {
                    let mut new_bricks = bricks.clone();
                    new_bricks.push(BrickDomain::Top);
                    BricksDomain::Value(new_bricks)
                }
                BricksDomain::Value(other_bricks) => {
                    let mut new_bricks = bricks.clone();
                    new_bricks.append(&mut other_bricks.clone());
                    BricksDomain::Value(new_bricks)
                }
            },
        }
    }

    /// Create a string domain that approximates float values.
    fn create_float_value_domain() -> Self {
        BricksDomain::from("[float inserted]".to_string())
    }

    /// Create a string domain that approximates char values.
    fn create_char_domain() -> Self {
        BricksDomain::from("[char inserted]".to_string())
    }

    /// Create a string domain that approximates integer values.
    fn create_integer_domain() -> Self {
        BricksDomain::from("[integer inserted]".to_string())
    }

    /// Create a string domain that approximates pointer values.
    fn create_pointer_value_domain() -> Self {
        BricksDomain::Top
    }

    /// Creates a top value of the domain.
    fn create_top_value_domain() -> Self {
        BricksDomain::Top
    }

    /// Create a string domain that represents an empty string.
    fn create_empty_string_domain() -> Self {
        BricksDomain::from("".to_string())
    }
}

impl AbstractDomain for BricksDomain {
    /// Takes care of merging lists of bricks
    fn merge(&self, other: &Self) -> Self {
        if self.is_top() || other.is_top() {
            Self::Top
        } else if self == other {
            self.clone()
        } else {
            let merged = self.widen(other);
            if !merged.is_top() {
                return merged.normalize();
            }

            merged
        }
    }

    /// Check if the value is *Top*.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }
}

impl HasTop for BricksDomain {
    /// Return a *Top* value
    fn top(&self) -> Self {
        Self::Top
    }
}

/// The single brick domain that represents a set of character sequences
/// as well as the minimum and maximum of the sum of their occurrences.
///
/// e.g. \[{"mo", "de"}\]^{1,2} represents the following set of strings:
/// {mo, de, momo, dede, mode, demo}.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub enum BrickDomain {
    /// The *Top* value represents the powerset over the alphabet
    /// of allowed characters with a minimum of 0 and a maximum of positive infinity.
    Top,
    /// The set of character sequences as well as the minimum and maximum of the sum of their occurrences.
    Value(Brick),
}

impl BrickDomain {
    /// Returns a new instance of the Brick Domain
    pub fn new(string: String) -> Self {
        let mut new_brick = Brick::new();
        let mut sequence: BTreeSet<String> = BTreeSet::new();
        sequence.insert(string);
        new_brick.set_sequence(sequence);
        new_brick.set_min(1);
        new_brick.set_max(1);

        BrickDomain::Value(new_brick)
    }

    /// Returns an empty string brick
    fn get_empty_brick_domain() -> Self {
        BrickDomain::Value(Brick::new())
    }

    /// Unwraps a brick value and panics if it's *Top*.
    fn unwrap_value(&self) -> Brick {
        match self {
            BrickDomain::Value(brick) => brick.clone(),
            _ => panic!("Unexpected Brick Domain type."),
        }
    }
}

impl From<String> for BricksDomain {
    /// Returns a new instance of the Bricks Domain
    fn from(string: String) -> Self {
        BricksDomain::Value(vec![BrickDomain::new(string)])
    }
}

impl AbstractDomain for BrickDomain {
    /// Takes care of merging single bricks by taking the union
    /// of the two brick's string sequences and the minimum and maximum
    /// of their respective min and max values.
    fn merge(&self, other: &Self) -> Self {
        if self.is_top() || other.is_top() {
            Self::Top
        } else {
            self.widen(other)
        }
    }

    /// Check if the value is *Top*.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }
}

impl fmt::Display for BrickDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrickDomain::Top => write!(f, "[T]"),
            BrickDomain::Value(brick) => {
                write!(
                    f,
                    "{:?}^({},{})",
                    brick.get_sequence(),
                    brick.get_min(),
                    brick.get_max(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests;
