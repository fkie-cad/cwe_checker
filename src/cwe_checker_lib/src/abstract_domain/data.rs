use super::{
    AbstractDomain, AbstractIdentifier, HasTop, Interval, RegisterDomain, SizedDomain,
    SpecializeByConditional, TryToBitvec, TryToInterval,
};
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::iter::FromIterator;

/// An abstract domain representing a set of base values plus offsets or an absolute value (or both).
///
/// The base values are represented as abstract IDs,
/// i.e. they are treated as variables with unknown absolute value.
/// For each base value the offset is given by an abstract domain `T`,
/// which should specialize in representing absolute values (e.g. an interval domain).
/// Note that the domain assumes pointer semantics for these values.
/// That means if one applies operations to the domain that are not used in pointer arithmetics,
/// the abstract ID of the base value might be removed from the domain.
///
/// If the domain also represents absolute values,
/// then the values are given by a single instance of the abstract domain `T`.
///
/// The domain also contains a flag to indicate that it includes `Top` values,
/// i.e. values of fully unknown origin and offset.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DataDomain<T: RegisterDomain> {
    /// The byte size of the represented values.
    size: ByteSize,
    /// A map from base values to the corresponding offset.
    relative_values: BTreeMap<AbstractIdentifier, T>,
    /// An absolute value if the domain may represent an absolute value.
    absolute_value: Option<T>,
    /// An indicator whether the domain also represents values for which both the base and the offset are unknown.
    contains_top_values: bool,
}

impl<T: RegisterDomain> DataDomain<T> {
    /// Returns true if the domain does not represent any value.
    ///
    /// The meaning of an empty value depends on the usage of the domain.
    /// E.g. it may indicate an impossible runtime state of a program in one analysis
    /// or simply no value of interest in another analysis.
    ///
    /// An empty value represents the bottom value in the partial order of the domain.
    pub fn is_empty(&self) -> bool {
        self.relative_values.is_empty()
            && self.absolute_value.is_none()
            && !self.contains_top_values
    }

    /// Return a new empty value with the given bytesize.
    pub fn new_empty(size: ByteSize) -> Self {
        DataDomain {
            size,
            relative_values: BTreeMap::new(),
            absolute_value: None,
            contains_top_values: false,
        }
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(
        &mut self,
        old_id: &AbstractIdentifier,
        new_id: &AbstractIdentifier,
        offset_adjustment: &T,
    ) {
        if let Some(old_offset) = self.relative_values.get(old_id) {
            let new_offset = old_offset.bin_op(BinOpType::IntAdd, offset_adjustment);
            self.relative_values.remove(old_id);
            self.relative_values.insert(new_id.clone(), new_offset);
        }
    }

    /// Return an iterator over all referenced abstract IDs.
    pub fn referenced_ids(&self) -> impl Iterator<Item = &AbstractIdentifier> {
        self.relative_values.keys()
    }

    /// Return the relative values contained in the domain.
    pub fn get_relative_values(&self) -> &BTreeMap<AbstractIdentifier, T> {
        &self.relative_values
    }

    /// Replace the map of relative values with the given one.
    pub fn set_relative_values(&mut self, relative_values: BTreeMap<AbstractIdentifier, T>) {
        self.relative_values = relative_values;
    }

    /// Return the absolute value contained in the domain if present
    pub fn get_absolute_value(&self) -> Option<&T> {
        self.absolute_value.as_ref()
    }

    /// Replace the absolute value contained in the domain with the given one.
    /// A value of `None` means that the domain does not contain an absolute value.
    pub fn set_absolute_value(&mut self, value: Option<T>) {
        self.absolute_value = value
    }

    /// Returns `true` if the domain contains `Top` values,
    /// i.e. values for which neither a value nor an abstract identifier is known.
    ///
    /// Note that the `DataDomain` itself has no maximal value,
    /// i.e. this does not indicate a `Top` value of the abstract domain.
    pub fn contains_top(&self) -> bool {
        self.contains_top_values
    }

    /// Indicate that the domain may contain `Top` values
    /// in addition to the contained absolute and relative values.
    ///
    /// This does not remove absolute or relative value information from the domain.
    pub fn set_contains_top_flag(&mut self) {
        self.contains_top_values = true;
    }

    /// Return a new value representing a variable plus an offset,
    /// where the variable is represented by the given abstract ID.
    pub fn from_target(id: AbstractIdentifier, offset: T) -> Self {
        DataDomain {
            size: offset.bytesize(),
            relative_values: BTreeMap::from_iter([(id, offset)]),
            absolute_value: None,
            contains_top_values: false,
        }
    }

    /// Return a new domain representing a set of relative values.
    /// Note that this function will panic if given an empty set as input.
    #[cfg(test)]
    pub fn from_target_map(targets: BTreeMap<AbstractIdentifier, T>) -> Self {
        DataDomain {
            size: targets.values().next().unwrap().bytesize(),
            relative_values: targets,
            absolute_value: None,
            contains_top_values: false,
        }
    }

    /// Remove all provided IDs from the list of relative values.
    pub fn remove_ids(&mut self, ids_to_remove: &BTreeSet<AbstractIdentifier>) {
        self.relative_values = self
            .relative_values
            .iter()
            .filter_map(|(id, offset)| {
                if ids_to_remove.get(id).is_none() {
                    Some((id.clone(), offset.clone()))
                } else {
                    None
                }
            })
            .collect();
    }

    /// Return the contained absolute value
    /// only if `self` contains no other (relative or `Top`) values.
    pub fn get_if_absolute_value(&self) -> Option<&T> {
        if self.relative_values.is_empty() && !self.contains_top_values {
            self.absolute_value.as_ref()
        } else {
            None
        }
    }

    /// Return the contained absolute value
    /// if `self` only contains absolute or `Top` values.
    fn get_if_absolute_value_or_top(&self) -> Option<&T> {
        if self.relative_values.is_empty() {
            self.absolute_value.as_ref()
        } else {
            None
        }
    }

    /// Return the target ID and offset of the contained relative value
    /// if `self` contains exactly one relative value and no absolute or `Top` values.
    pub fn get_if_unique_target(&self) -> Option<(&AbstractIdentifier, &T)> {
        if self.relative_values.len() == 1
            && self.absolute_value.is_none()
            && !self.contains_top_values
        {
            Some(self.relative_values.iter().next().unwrap())
        } else {
            None
        }
    }

    /// Compute `self + rhs`.
    fn compute_add(&self, rhs: &Self) -> Self {
        if let Some(offset) = self.get_if_absolute_value_or_top() {
            let mut result = rhs.add_offset(offset);
            result.contains_top_values |= self.contains_top_values;
            result
        } else if let Some(offset) = rhs.get_if_absolute_value_or_top() {
            let mut result = self.add_offset(offset);
            result.contains_top_values |= rhs.contains_top_values;
            result
        } else {
            self.preserve_relative_targets_for_binop(rhs)
        }
    }

    /// Add `offset` to all contained absolute and relative values of `self` and return the result.
    pub fn add_offset(&self, offset: &T) -> Self {
        DataDomain {
            size: self.size,
            relative_values: self
                .relative_values
                .iter()
                .map(|(id, old_offset)| (id.clone(), old_offset.bin_op(BinOpType::IntAdd, offset)))
                .collect(),
            absolute_value: self
                .absolute_value
                .as_ref()
                .map(|old_offset| old_offset.bin_op(BinOpType::IntAdd, offset)),
            contains_top_values: self.contains_top_values,
        }
    }

    /// Subtract `offset` from all contained absolute and relative values of `self` and return the result.
    pub fn subtract_offset(&self, offset: &T) -> Self {
        DataDomain {
            size: self.size,
            relative_values: self
                .relative_values
                .iter()
                .map(|(id, old_offset)| (id.clone(), old_offset.bin_op(BinOpType::IntSub, offset)))
                .collect(),
            absolute_value: self
                .absolute_value
                .as_ref()
                .map(|old_offset| old_offset.bin_op(BinOpType::IntSub, offset)),
            contains_top_values: self.contains_top_values,
        }
    }

    /// Compute `self - rhs`.
    fn compute_sub(&self, rhs: &Self) -> Self {
        if self.is_empty() || rhs.is_empty() {
            // The result is again empty.
            Self::new_empty(self.bytesize())
        } else if rhs.relative_values.is_empty() {
            // Subtract a (possibly unknown) offset
            let offset = rhs
                .absolute_value
                .as_ref()
                .cloned()
                .unwrap_or_else(|| T::new_top(self.size));
            let mut result = self.subtract_offset(&offset);
            result.contains_top_values = result.contains_top_values || rhs.contains_top_values;
            result
        } else if !self.contains_top_values
            && !rhs.contains_top_values
            && self.absolute_value.is_none()
            && rhs.absolute_value.is_none()
            && self.relative_values.len() == 1
            && rhs.relative_values.len() == 1
        {
            // Compute an offset by subtracting pointers
            let (lhs_id, lhs_offset) = self.relative_values.iter().next().unwrap();
            let (rhs_id, rhs_offset) = rhs.relative_values.iter().next().unwrap();
            if lhs_id == rhs_id {
                DataDomain {
                    size: self.bytesize(),
                    relative_values: BTreeMap::new(),
                    absolute_value: Some(lhs_offset.bin_op(BinOpType::IntSub, rhs_offset)),
                    contains_top_values: false,
                }
            } else {
                // `self` and `rhs` are relative different abstract IDs.
                DataDomain {
                    size: self.bytesize(),
                    relative_values: BTreeMap::from_iter([
                        (lhs_id.clone(), T::new_top(self.bytesize())),
                        (rhs_id.clone(), T::new_top(self.bytesize())),
                    ]),
                    absolute_value: Some(T::new_top(self.bytesize())),
                    contains_top_values: false,
                }
            }
        } else {
            // We do not know whether the result is a relative or absolute value.
            self.preserve_relative_targets_for_binop(rhs)
        }
    }

    /// Compute the result of a byte size preserving binary operation
    /// where it is unknown whether the result is an absolute or relative value.
    ///
    /// This function conservately approximates all offsets with `Top`.
    fn preserve_relative_targets_for_binop(&self, rhs: &Self) -> Self {
        if self.is_empty() || rhs.is_empty() {
            // The result is again empty.
            return Self::new_empty(self.bytesize());
        }
        let mut relative_values = BTreeMap::new();
        for id in self.relative_values.keys() {
            relative_values.insert(id.clone(), T::new_top(self.bytesize()));
        }
        for id in rhs.relative_values.keys() {
            relative_values.insert(id.clone(), T::new_top(self.bytesize()));
        }
        DataDomain {
            size: self.bytesize(),
            relative_values,
            absolute_value: Some(T::new_top(self.bytesize())),
            contains_top_values: self.contains_top_values || rhs.contains_top_values,
        }
    }
}

impl<T: SpecializeByConditional + RegisterDomain> SpecializeByConditional for DataDomain<T> {
    fn add_signed_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .map(|value| value.add_signed_less_equal_bound(bound).ok())
            .flatten();
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_unsigned_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .map(|value| value.add_unsigned_less_equal_bound(bound).ok())
            .flatten();
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_signed_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .map(|value| value.add_signed_greater_equal_bound(bound).ok())
            .flatten();
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_unsigned_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .map(|value| value.add_unsigned_greater_equal_bound(bound).ok())
            .flatten();
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_not_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .map(|value| value.add_not_equal_bound(bound).ok())
            .flatten();
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn intersect(self, other: &Self) -> Result<Self, Error> {
        let result = match (self.contains_top_values, other.contains_top_values) {
            // If only one input value contains top elements, then the other input is the best approximation for the intersection.
            (true, false) => other.clone(),
            (false, true) => self,
            // Else we can compute the intersection field-wise.
            (true, true) | (false, false) => {
                let relative_values = self
                    .relative_values
                    .iter()
                    .filter_map(|(id, offset)| {
                        other
                            .relative_values
                            .get(id)
                            .map(|other_offset| {
                                if let Ok(intersected_offset) =
                                    offset.clone().intersect(other_offset)
                                {
                                    Some((id.clone(), intersected_offset))
                                } else {
                                    None
                                }
                            })
                            .flatten()
                    })
                    .collect();
                let absolute_value = if let (Some(value), Some(other_value)) =
                    (&self.absolute_value, &other.absolute_value)
                {
                    value.clone().intersect(other_value).ok()
                } else {
                    None
                };
                DataDomain {
                    size: self.bytesize(),
                    relative_values,
                    absolute_value,
                    contains_top_values: self.contains_top_values && other.contains_top_values,
                }
            }
        };
        if result.is_empty() {
            Err(anyhow!("Domain is empty."))
        } else {
            Ok(result)
        }
    }
}

impl<T: RegisterDomain> SizedDomain for DataDomain<T> {
    /// Return the bytesize of `self`.
    fn bytesize(&self) -> ByteSize {
        self.size
    }

    /// Return a new *Top* element with the given bytesize.
    ///
    /// Note that `DataDomain` technically does not have a `Top` element with respect to the partial order.
    /// Instead a `Top` element here represents a non-empty value
    /// for which nothing is known about the contained values.
    fn new_top(bytesize: ByteSize) -> Self {
        DataDomain {
            size: bytesize,
            relative_values: BTreeMap::new(),
            absolute_value: None,
            contains_top_values: true,
        }
    }
}

impl<T: RegisterDomain> HasTop for DataDomain<T> {
    /// Generate a new *Top* element with the same bytesize as `self`.
    fn top(&self) -> Self {
        DataDomain::new_top(self.bytesize())
    }
}

impl<T: RegisterDomain> RegisterDomain for DataDomain<T> {
    /// Compute the (abstract) result of a binary operation
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        use BinOpType::*;
        if let (Some(left), Some(right)) =
            (self.get_if_absolute_value(), rhs.get_if_absolute_value())
        {
            // Case 1: A binary operation of absolute values.
            left.bin_op(op, right).into()
        } else {
            match op {
                // Case 2: Addition
                IntAdd => self.compute_add(rhs),
                // Case 3: Subtraction
                IntSub => self.compute_sub(rhs),
                // Case 4: An operation where the result may be a pointer.
                IntAnd | IntOr | IntXOr => self.preserve_relative_targets_for_binop(rhs),
                // Case 5: An operation with result being a boolean.
                IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual
                | IntCarry | IntSCarry | IntSBorrow | BoolXOr | BoolOr | BoolAnd | FloatEqual
                | FloatNotEqual | FloatLess | FloatLessEqual => {
                    if self.is_empty() || rhs.is_empty() {
                        Self::new_empty(ByteSize::new(1))
                    } else {
                        T::new_top(ByteSize::new(1)).into()
                    }
                }
                // Case 6: An operation that does not change the byte size.
                IntMult | IntDiv | IntSDiv | IntRem | IntSRem | IntLeft | IntRight | IntSRight
                | FloatAdd | FloatSub | FloatMult | FloatDiv => {
                    if self.is_empty() || rhs.is_empty() {
                        Self::new_empty(self.bytesize())
                    } else {
                        Self::new_top(self.bytesize())
                    }
                }
                // Case 7: Concatenating two bitvectors
                Piece => {
                    if self.is_empty() || rhs.is_empty() {
                        Self::new_empty(self.bytesize() + rhs.bytesize())
                    } else {
                        Self::new_top(self.bytesize() + rhs.bytesize())
                    }
                }
            }
        }
    }

    /// Compute the (abstract) result of a unary operation
    fn un_op(&self, op: UnOpType) -> Self {
        let size = match op {
            UnOpType::BoolNegate | UnOpType::FloatNaN => ByteSize::new(1),
            _ => self.bytesize(),
        };
        DataDomain {
            size,
            relative_values: BTreeMap::new(),
            absolute_value: self.absolute_value.as_ref().map(|val| val.un_op(op)),
            contains_top_values: self.contains_top_values || !self.relative_values.is_empty(),
        }
    }

    /// extract a sub-bitvector
    fn subpiece(&self, low_byte: ByteSize, size: ByteSize) -> Self {
        if low_byte == ByteSize::new(0) && size == self.bytesize() {
            // The operation is a no-op
            self.clone()
        } else {
            DataDomain {
                size,
                relative_values: BTreeMap::new(),
                absolute_value: self
                    .absolute_value
                    .as_ref()
                    .map(|val| val.subpiece(low_byte, size)),
                contains_top_values: self.contains_top_values || !self.relative_values.is_empty(),
            }
        }
    }

    /// Cast a bitvector using the given cast type
    fn cast(&self, kind: CastOpType, width: ByteSize) -> Self {
        DataDomain {
            size: width,
            relative_values: BTreeMap::new(),
            absolute_value: self
                .absolute_value
                .as_ref()
                .map(|val| val.cast(kind, width)),
            contains_top_values: self.contains_top_values || !self.relative_values.is_empty(),
        }
    }
}

impl<T: RegisterDomain> AbstractDomain for DataDomain<T> {
    // Merge `self` with `other`.
    fn merge(&self, other: &Self) -> Self {
        let mut relative_values = self.relative_values.clone();
        for (id, offset_other) in other.relative_values.iter() {
            relative_values
                .entry(id.clone())
                .and_modify(|offset| *offset = offset.merge(offset_other))
                .or_insert_with(|| offset_other.clone());
        }
        let absolute_value = match (&self.absolute_value, &other.absolute_value) {
            (Some(left), Some(right)) => Some(left.merge(right)),
            (Some(val), None) | (None, Some(val)) => Some(val.clone()),
            (None, None) => None,
        };
        DataDomain {
            size: self.bytesize(),
            relative_values,
            absolute_value,
            contains_top_values: self.contains_top_values || other.contains_top_values,
        }
    }

    /// Return whether the element represents a top element or not.
    ///
    /// Note that `DataDomain` technically does not have a `Top` element with respect to the partial order.
    /// Instead a `Top` element here represents a non-empty value
    /// for which nothing is known about the contained values.
    fn is_top(&self) -> bool {
        self.relative_values.is_empty() && self.absolute_value.is_none() && self.contains_top_values
    }
}

impl<T: RegisterDomain> From<T> for DataDomain<T> {
    fn from(value: T) -> Self {
        Self {
            size: value.bytesize(),
            relative_values: BTreeMap::new(),
            absolute_value: Some(value),
            contains_top_values: false,
        }
    }
}

impl<T: RegisterDomain + From<Bitvector>> From<Bitvector> for DataDomain<T> {
    fn from(bitvector: Bitvector) -> Self {
        let val: T = bitvector.into();
        val.into()
    }
}

impl<T: RegisterDomain + TryToBitvec> TryToBitvec for DataDomain<T> {
    /// If the domain represents a single, absolute value, return it.
    fn try_to_bitvec(&self) -> Result<Bitvector, Error> {
        if !self.relative_values.is_empty() || self.contains_top_values {
            Err(anyhow!("May contain non-absolute values."))
        } else if let Some(val) = &self.absolute_value {
            val.try_to_bitvec()
        } else {
            Err(anyhow!("Domain is empty."))
        }
    }
}

impl<T: RegisterDomain + TryToInterval> TryToInterval for DataDomain<T> {
    /// If the domain represents (or can be widened to) an interval of absolute values, return the interval.
    fn try_to_interval(&self) -> Result<Interval, Error> {
        if !self.relative_values.is_empty() || self.contains_top_values {
            Err(anyhow!("May contain non-absolute values."))
        } else if let Some(val) = &self.absolute_value {
            val.try_to_interval()
        } else {
            Err(anyhow!("Domain is empty."))
        }
    }
}

impl<T: RegisterDomain> std::ops::Add for DataDomain<T> {
    type Output = DataDomain<T>;

    fn add(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntAdd, &rhs)
    }
}

impl<T: RegisterDomain> std::ops::Sub for DataDomain<T> {
    type Output = DataDomain<T>;

    fn sub(self, rhs: Self) -> Self {
        self.bin_op(BinOpType::IntSub, &rhs)
    }
}

impl<T: RegisterDomain + Display> DataDomain<T> {
    /// Get a more compact json-representation of the data domain.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        let mut values = Vec::new();
        if !self.relative_values.is_empty() {
            let target_iter = self.relative_values.iter().map(|(id, offset)| {
                (
                    format!("{}", id),
                    serde_json::Value::String(format!("{}", offset)),
                )
            });
            let targets = serde_json::Value::Object(target_iter.collect());
            let mut obj_map = serde_json::Map::new();
            obj_map.insert("Pointer".to_string(), targets);
            values.push(serde_json::Value::Object(obj_map));
        }
        if let Some(absolute_value) = &self.absolute_value {
            values.push(serde_json::Value::String(format!(
                "Value: {}",
                absolute_value
            )));
        }
        if self.contains_top_values {
            values.push(serde_json::Value::String(format!(
                "Top:{}",
                self.bytesize()
            )));
        }
        match values.len() {
            0 => serde_json::Value::String(format!("Empty:{}", self.bytesize())),
            1 => values.pop().unwrap(),
            _ => serde_json::Value::Array(values),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    type Data = DataDomain<BitvectorDomain>;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(Bitvector::from_i64(value))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(name.into(), ByteSize::new(8)),
        )
    }

    fn new_pointer(location: &str, offset: i64) -> Data {
        DataDomain {
            size: ByteSize::new(8),
            relative_values: BTreeMap::from_iter([(new_id(location), bv(offset))]),
            absolute_value: None,
            contains_top_values: false,
        }
    }

    fn new_value(value: i64) -> Data {
        Data::from(bv(value))
    }

    #[test]
    fn data_merge() {
        let pointer = new_pointer("RAX".into(), 0);
        let value = new_value(42);
        let merged_data = pointer.merge(&value);
        assert_eq!(pointer.merge(&pointer), pointer);
        assert_eq!(merged_data.relative_values, pointer.relative_values);
        assert_eq!(merged_data.absolute_value, value.absolute_value);

        let other_value = new_value(-1);
        let merged_data = value.merge(&other_value);
        assert!(merged_data.relative_values.is_empty());
        assert_eq!(
            merged_data.absolute_value,
            Some(BitvectorDomain::new_top(ByteSize::new(8)))
        );

        let other_pointer = new_pointer("RBX".into(), 10);
        let merged_data = pointer.merge(&other_pointer);
        assert_eq!(
            merged_data.relative_values.get(&new_id("RAX")),
            Some(&bv(0))
        );
        assert_eq!(
            merged_data.relative_values.get(&new_id("RBX")),
            Some(&bv(10))
        );
    }

    #[test]
    fn data_register_domain() {
        use BinOpType::*;
        let data = new_value(42);
        assert_eq!(data.bytesize(), ByteSize::new(8));

        let three = new_value(3);
        let pointer = new_pointer("Rax".into(), 0);
        assert_eq!(data.bin_op(IntAdd, &three), new_value(45));
        assert_eq!(pointer.bin_op(IntAdd, &three), new_pointer("Rax".into(), 3));
        assert_eq!(three.un_op(UnOpType::Int2Comp), new_value(-3));

        assert_eq!(
            three.subpiece(ByteSize::new(0), ByteSize::new(4)),
            BitvectorDomain::Value(Bitvector::from_i32(3)).into()
        );

        assert_eq!(
            data.cast(CastOpType::IntSExt, ByteSize::new(16)).bytesize(),
            ByteSize::new(16)
        );

        let one: Data = BitvectorDomain::Value(Bitvector::from_i32(1)).into();
        let two: Data = BitvectorDomain::Value(Bitvector::from_i32(2)).into();
        let concat = new_value((1 << 32) + 2);
        assert_eq!(one.bin_op(Piece, &two), concat);
    }

    #[test]
    fn remove_ids() {
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), bv(1));
        targets.insert(new_id("Rbx"), bv(2));
        let mut data = Data::new_empty(ByteSize::new(8));
        data.relative_values = targets;

        let mut ids_to_remove = BTreeSet::new();
        ids_to_remove.insert(new_id("Rbx"));
        ids_to_remove.insert(new_id("Rcx"));

        data.remove_ids(&ids_to_remove);
        assert_eq!(
            data.referenced_ids()
                .cloned()
                .collect::<Vec<AbstractIdentifier>>(),
            vec![new_id("Rax")]
        );

        data = bv(42).into();
        data.remove_ids(&ids_to_remove);
        assert_eq!(data, bv(42).into());
    }

    #[test]
    fn float_nan_bytesize() {
        let top_value: DataDomain<BitvectorDomain> = DataDomain::new_top(ByteSize::new(8));
        let result = top_value.un_op(UnOpType::FloatNaN);
        assert!(result.is_top());
        assert_eq!(result.bytesize(), ByteSize::new(1));
    }
}
