//! This module contains the Character Inclusion Domain (CI).
//!
//! This domain considers the characters of a string and distinguishes
//! between two scenarios which are stored in different HashSets.
//! - The first set contains characters that are certainly contained in
//!   the string.
//! - The second set contains characters that may be in the string.
//!
//! This distinction is made when two CI domains merge.
//! Furthermore, the CI domain does not preserve information about the order of characters.
//! The *Top* value of the CI domain stands for an empty set of certainly
//! contained characters and the whole alphabet of allowed characters for the possibly contained characters.
//!
//! The following presents an example which shows how the CI domain works:
//!  1. When a string is assigned to the CI domain its unique characters are stored in both
//!    sets. e.g. "Hello, World!" => ({H,e,l,o,',',' ',W,o,r,d}, {H,e,l,o,',',' ',W,o,r,d})
//!  2. When two strings are concatenated, the union of the two sets of the two domains is taken.
//!     e.g. "Hello, " + "World" => ({H,e,l,o,',',' '} v {W,o,r,d}, {H,e,l,o,',',' '} v {W,o,r,d})
//!  3. When two domains are merged, the intersection of the certain sets and the union of possible sets are taken.
//!     e.g. ({H,e,l,o,',',' '}, {H,e,l,o,',',' '}) v ({W,o,r,l,d}, {W,o,r,l,d}) => ({l,o}, {H,e,l,o,',',' ',W,o,r,d})

use std::collections::HashSet;

use crate::prelude::*;

use super::{AbstractDomain, HasTop};

/// The `CharacterInclusionDomain` is a abstract domain describing the characters a string certainly has.
/// and the characters a string may have.
///
/// The value comprises of a set of certainly contained characters and a set of possibly contained characters
/// while the *Top* value does not get any data. However, the *Top* value stands for an empty set of certainly
/// contained characters and the whole alphabet of allowed characters for the possibly contained characters.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum CharacterInclusionDomain {
    /// The *Top* value stands for an empty set of certainly contained characters and
    /// the whole alphabet of allowed characters for the possibly contained characters.
    Top,
    /// The set of certainly contained characters and a set of possibly contained characters
    Value((HashSet<char>, HashSet<char>)),
}

impl CharacterInclusionDomain {
    /// Unwraps the values from the Character Inclusion Domain
    pub fn unwrap_value(&self) -> (HashSet<char>, HashSet<char>) {
        match self {
            CharacterInclusionDomain::Value(value) => value.clone(),
            _ => panic!("Unexpected Character Inclusion type."),
        }
    }
}

impl AbstractDomain for CharacterInclusionDomain {
    /// Merge two values; Takes the intersection of the certainly contained characters
    /// and the union of the possibly contained characters.
    /// Returns *Top* if either Domain represents it.
    fn merge(&self, other: &Self) -> Self {
        if self.is_top() || other.is_top() {
            Self::Top
        } else {
            let (self_certain, self_possible) = self.unwrap_value();
            let (other_certain, other_possible) = other.unwrap_value();
            Self::Value((
                self_certain.intersection(&other_certain).cloned().collect(),
                self_possible.union(&other_possible).cloned().collect(),
            ))
        }
    }

    /// Check if the value is *Top*.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }
}

impl HasTop for CharacterInclusionDomain {
    /// Return a *Top* value
    fn top(&self) -> Self {
        CharacterInclusionDomain::Top
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ci(concrete: &str) -> CharacterInclusionDomain {
        let abstract_set: HashSet<char> = concrete.chars().into_iter().collect();
        CharacterInclusionDomain::Value((abstract_set.clone(), abstract_set.clone()))
    }

    #[test]
    fn merging() {
        let first = ci("abc");
        let second = ci("def");
        let third = ci("dabc");
        let possible_set: HashSet<char> = "abcdef".chars().into_iter().collect();
        let certain_set: HashSet<char> = "d".chars().into_iter().collect();

        assert_eq!(
            first.merge(&second),
            CharacterInclusionDomain::Value((HashSet::new(), possible_set.clone()))
        );
        assert_eq!(
            third.merge(&second),
            CharacterInclusionDomain::Value((certain_set, possible_set))
        );
        assert_eq!(
            first.merge(&CharacterInclusionDomain::Top),
            CharacterInclusionDomain::Top
        );
        assert_eq!(
            CharacterInclusionDomain::Top.merge(&CharacterInclusionDomain::Top),
            CharacterInclusionDomain::Top
        );
    }
}
