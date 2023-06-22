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

use std::{collections::BTreeSet, fmt};

use crate::prelude::*;
use std::fmt::Debug;

use super::{AbstractDomain, DomainInsertion, HasTop};

/// The `CharacterInclusionDomain` is a abstract domain describing the characters a string certainly has
/// and the characters a string may have.
///
/// The value comprises of a set of certainly contained characters and a set of possibly contained characters
/// while the *Top* value does not get any data. However, the *Top* value stands for an empty set of certainly
/// contained characters and the whole alphabet of allowed characters for the possibly contained characters.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub enum CharacterInclusionDomain {
    /// The *Top* value stands for an empty set of certainly contained characters and
    /// the whole alphabet of allowed characters for the possibly contained characters.
    Top,
    /// The set of certainly contained characters and a set of possibly contained characters
    Value((CharacterSet, CharacterSet)),
}

impl CharacterInclusionDomain {
    /// Unwraps the values from the Character Inclusion Domain
    pub fn unwrap_value(&self) -> (CharacterSet, CharacterSet) {
        match self {
            CharacterInclusionDomain::Value(value) => value.clone(),
            _ => panic!("Unexpected Character Inclusion type."),
        }
    }
}

impl DomainInsertion for CharacterInclusionDomain {
    /// Append string domain as part of a concatenation. (different to merge)
    fn append_string_domain(&self, string_domain: &Self) -> CharacterInclusionDomain {
        match self {
            CharacterInclusionDomain::Value((self_certain, self_possible)) => match string_domain {
                CharacterInclusionDomain::Value((other_certain, other_possible)) => {
                    CharacterInclusionDomain::Value((
                        self_certain.union(other_certain.clone()),
                        self_possible.union(other_possible.clone()),
                    ))
                }
                CharacterInclusionDomain::Top => {
                    CharacterInclusionDomain::Value((self_certain.clone(), CharacterSet::Top))
                }
            },
            CharacterInclusionDomain::Top => match string_domain {
                CharacterInclusionDomain::Value((other_certain, _)) => {
                    CharacterInclusionDomain::Value((other_certain.clone(), CharacterSet::Top))
                }
                CharacterInclusionDomain::Top => CharacterInclusionDomain::Top,
            },
        }
    }

    /// Create a string domain that approximates float values.
    fn create_float_value_domain() -> Self {
        let float_character_set: BTreeSet<char> = vec![
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '-', 'a', 'i', 'n', 'f', 'e',
            'E',
        ]
        .into_iter()
        .collect();
        CharacterInclusionDomain::Value((
            CharacterSet::Value(vec![].into_iter().collect()),
            CharacterSet::Value(float_character_set),
        ))
    }

    /// Create a string domain that approximates char values.
    fn create_char_domain() -> Self {
        CharacterInclusionDomain::Top
    }

    /// Create a string domain that approximates integer values.
    fn create_integer_domain() -> Self {
        let integer_character_set: BTreeSet<char> =
            vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-']
                .into_iter()
                .collect();
        CharacterInclusionDomain::Value((
            CharacterSet::Value(vec![].into_iter().collect()),
            CharacterSet::Value(integer_character_set),
        ))
    }

    /// Create a string domain that approximates pointer values.
    fn create_pointer_value_domain() -> Self {
        CharacterInclusionDomain::Top
    }

    /// Creates a top value of the domain.
    fn create_top_value_domain() -> Self {
        CharacterInclusionDomain::Top
    }

    /// Create a string domain that represents an empty string.
    fn create_empty_string_domain() -> Self {
        CharacterInclusionDomain::from("".to_string())
    }
}

impl From<String> for CharacterInclusionDomain {
    fn from(string: String) -> Self {
        let characters: BTreeSet<char> = string.chars().collect();
        CharacterInclusionDomain::Value((
            CharacterSet::Value(characters.clone()),
            CharacterSet::Value(characters),
        ))
    }
}

impl AbstractDomain for CharacterInclusionDomain {
    /// Merge two values; Takes the intersection of the certainly contained characters
    /// and the union of the possibly contained characters.
    /// Returns *Top* if either Domain represents it.
    fn merge(&self, other: &Self) -> Self {
        if self.is_top() || other.is_top() {
            Self::Top
        } else if self == other {
            self.clone()
        } else {
            let (self_certain, self_possible) = self.unwrap_value();
            let (other_certain, other_possible) = other.unwrap_value();
            Self::Value((
                self_certain.intersection(other_certain),
                self_possible.union(other_possible),
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

impl fmt::Display for CharacterInclusionDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CharacterInclusionDomain::Top => write!(f, "Top"),
            CharacterInclusionDomain::Value((certain_set, possible_set)) => {
                write!(f, "Certain: {certain_set}, Possible: {possible_set}")
            }
        }
    }
}

/// A domain that represents character sets.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub enum CharacterSet {
    /// The *Top* value represents a character set of all allowed characters.
    Top,
    /// Represents a real subset of all allowed characters.
    Value(BTreeSet<char>),
}

impl CharacterSet {
    /// Unwraps the values from the CharacterSet
    pub fn unwrap_value(&self) -> BTreeSet<char> {
        match self {
            CharacterSet::Value(value) => value.clone(),
            _ => panic!("Unexpected CharacterSet type."),
        }
    }

    /// Takes the intersection of two character sets.
    /// None of the sets should be *Top* since otherwise
    /// the whole CharacterInclusionDomain would be *Top*
    /// which is checked beforehand.
    pub fn intersection(&self, other: Self) -> Self {
        if self.is_top() || other.is_top() {
            panic!("Unexpected Top Value for CharacterSet intersection.")
        }
        CharacterSet::Value(
            self.unwrap_value()
                .intersection(&other.unwrap_value())
                .cloned()
                .collect(),
        )
    }

    /// Takes the union of two character sets.
    /// If either of them is *Top* the union is *Top*.
    /// Otherwise the standard set union is taken.
    pub fn union(&self, other: Self) -> Self {
        if self.is_top() || other.is_top() {
            return CharacterSet::Top;
        }

        CharacterSet::Value(
            self.unwrap_value()
                .union(&other.unwrap_value())
                .cloned()
                .collect(),
        )
    }

    /// Check if the value is *Top*.
    fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }
}

impl HasTop for CharacterSet {
    /// Return a *Top* value
    fn top(&self) -> Self {
        CharacterSet::Top
    }
}

impl fmt::Display for CharacterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CharacterSet::Top => write!(f, "Top"),
            CharacterSet::Value(char_set) => {
                write!(f, "{char_set:?}")
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl CharacterInclusionDomain {
        pub fn ci(concrete: &str) -> CharacterInclusionDomain {
            let abstract_set = CharacterSet::Value(concrete.chars().into_iter().collect());
            CharacterInclusionDomain::Value((abstract_set.clone(), abstract_set.clone()))
        }
    }

    #[test]
    fn merging() {
        let first = CharacterInclusionDomain::ci("abc");
        let second = CharacterInclusionDomain::ci("def");
        let third = CharacterInclusionDomain::ci("dabc");
        let possible_set = CharacterSet::Value("abcdef".chars().into_iter().collect());
        let certain_set = CharacterSet::Value("d".chars().into_iter().collect());

        assert_eq!(
            first.merge(&second),
            CharacterInclusionDomain::Value((
                CharacterSet::Value(BTreeSet::new()),
                possible_set.clone()
            ))
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
