//! This module contains the Brick structure.
//! The Brick structure represents the set of all strings that can be built
//! through concatenation of a given sequence of strings with upper and lower boundaries.
//!
//! For instance, let \[{"mo", "de"}\]^{1,2} be a Brick. The following set of strings is
//! constructed through the aforementioned Brick:
//!    - {mo, de, momo, dede, mode, demo}

use std::collections::BTreeSet;

use crate::prelude::*;
use itertools::Itertools;

/// A single Brick with the set of strings, a minimum and maximum bound.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Brick {
    sequence: BTreeSet<String>,
    min: u32,
    max: u32,
}

impl Default for Brick {
    fn default() -> Self {
        Self::new()
    }
}

impl Brick {
    /// Creates a new instance of the Brick struct.
    pub fn new() -> Self {
        Brick {
            sequence: BTreeSet::new(),
            min: 0,
            max: 0,
        }
    }

    /// Set the sequence of the Brick.
    pub fn set_sequence(&mut self, sequence: BTreeSet<String>) {
        self.sequence = sequence;
    }

    /// Set the minimum bound for the element occurrences in the Brick.
    pub fn set_min(&mut self, min: u32) {
        self.min = min;
    }

    /// Set the maximum bound for the element occurrences in the Brick.
    pub fn set_max(&mut self, max: u32) {
        self.max = max;
    }

    /// Returns a reference to the string sequence in the brick.
    pub fn get_sequence(&self) -> &BTreeSet<String> {
        &self.sequence
    }

    /// Returns the minimum occurrence of the sequences contained in the brick.
    pub fn get_min(&self) -> u32 {
        self.min
    }

    /// Returns the maximum occurrence of the sequences contained in the brick.
    pub fn get_max(&self) -> u32 {
        self.max
    }

    /// Checks whether a brick represents an empty string (Rule 1)
    pub fn is_empty_string(&self) -> bool {
        if self.sequence.is_empty() && self.min == 0 && self.max == 0 {
            return true;
        }
        false
    }

    /// **merge** bricks with the same indices max = 1, min = 1, in a new single brick
    /// with the new string set being the concatenation of the former two. e.g. B0 = \[{a,cd}\]^{1,1}
    /// and B1 = \[{b,ef}\]^{1,1} become B_new = \[{ab, aef, cdb, cdef}\]^{1,1}.
    pub fn merge_bricks_with_bound_one(&self, other: Brick) -> Self {
        let product = self
            .sequence
            .iter()
            .cartesian_product(other.sequence.iter())
            .collect_vec();
        let sequence: BTreeSet<String> = product
            .iter()
            .map(|&(str1, str2)| str1.clone() + str2)
            .collect();

        Brick {
            sequence,
            min: 1,
            max: 1,
        }
    }

    /// **transform** a brick in which the number of applications is constant (min = max) into one in which
    /// min = max = 1. e.g. B = \[{a,b}\]^{2,2} => B_new = \[{aa, ab, ba, bb}\]^{1,1}.
    pub fn transform_brick_with_min_max_equal(&self, length: usize) -> Self {
        let permutations: BTreeSet<String> =
            Self::generate_permutations_of_fixed_length(length, &self.sequence, Vec::new())
                .into_iter()
                .collect();
        Brick {
            sequence: permutations,
            min: 1,
            max: 1,
        }
    }

    /// **merge** two bricks in which the set of strings is the same. e.g. B1 = \[S\]^{m1, M1}
    /// and B2 = \[S\]^{m2, M2} => B_new = \[S\]^{m1+m2, M1+M2}
    pub fn merge_bricks_with_equal_content(&self, other: Brick) -> Self {
        Brick {
            sequence: self.sequence.clone(),
            min: self.min + other.min,
            max: self.max + other.max,
        }
    }

    /// **break** a single brick with min >= 1 and max != min into two simpler bricks where B = \[S\]^{min,max} =>
    /// B1 = \[S^min\]^{1,1}, B2 = \[S\]^{0, max-min}.
    /// e.g. B = \[{a}\]^{2,5} => B1 = \[{aa}\]^{1,1}, B2 = \[{a}\]^{0,3}
    pub fn break_single_brick_into_simpler_bricks(&self) -> (Self, Self) {
        let brick_1 = self.transform_brick_with_min_max_equal(self.min as usize);
        let brick_2 = Brick {
            sequence: self.sequence.clone(),
            min: 0,
            max: self.max - self.min,
        };

        (brick_1, brick_2)
    }

    /// Recursive function to generate sequence permutations of fixed length.
    /// For instance, \[{a,b}\] with length = 2 becomes \[{aa, ab, ba, bb}\]
    /// Note that the length can also be greater or smaller than
    /// the number of elements in the sequence.
    pub fn generate_permutations_of_fixed_length(
        length: usize,
        sequence: &BTreeSet<String>,
        generated: Vec<String>,
    ) -> Vec<String> {
        let mut new_gen: Vec<String> = Vec::new();
        for s in sequence.iter() {
            if generated.is_empty() {
                new_gen.push(s.to_string());
            } else {
                for g in generated.iter() {
                    new_gen.push(g.clone() + s);
                }
            }
        }

        if new_gen.get(0).unwrap().len() < length {
            return Self::generate_permutations_of_fixed_length(length, sequence, new_gen);
        }

        new_gen
    }
}
