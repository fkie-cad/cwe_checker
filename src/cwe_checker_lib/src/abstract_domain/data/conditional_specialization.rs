use super::*;

/// Compute the intersection of relative targets for two `DataDomain` instances.
fn intersect_relative_values<T: SpecializeByConditional + RegisterDomain>(
    values_left: &BTreeMap<AbstractIdentifier, T>,
    values_right: &BTreeMap<AbstractIdentifier, T>,
) -> BTreeMap<AbstractIdentifier, T> {
    values_left
        .iter()
        .filter_map(|(id, offset)| {
            values_right.get(id).and_then(|other_offset| {
                if let Ok(intersected_offset) = offset.clone().intersect(other_offset) {
                    Some((id.clone(), intersected_offset))
                } else {
                    None
                }
            })
        })
        .collect()
}

impl<T: SpecializeByConditional + RegisterDomain> SpecializeByConditional for DataDomain<T> {
    fn add_signed_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .and_then(|value| value.add_signed_less_equal_bound(bound).ok());
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_unsigned_less_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .and_then(|value| value.add_unsigned_less_equal_bound(bound).ok());
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_signed_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .and_then(|value| value.add_signed_greater_equal_bound(bound).ok());
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_unsigned_greater_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .and_then(|value| value.add_unsigned_greater_equal_bound(bound).ok());
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    fn add_not_equal_bound(mut self, bound: &Bitvector) -> Result<Self, Error> {
        self.absolute_value = self
            .absolute_value
            .and_then(|value| value.add_not_equal_bound(bound).ok());
        if self.is_empty() {
            Err(anyhow!("Empty value"))
        } else {
            Ok(self)
        }
    }

    /// Compute the intersetion of two DataDomains.
    /// 
    /// Note that this implementation is unsound for several reasons:
    /// - For example, it assumes that two different relative values cannot intersect.
    /// But that is not true if their offfsets are big enough
    /// or if the relative values do in fact reference the same object despite having different identifiers.
    /// - If intersecting relative values with absolute values we represent the result with the absolute values.
    /// But depending on the use-case an approximation by the relative values could be more precise.
    fn intersect(self, other: &Self) -> Result<Self, Error> {
        let mut result = match (self.contains_top_values, other.contains_top_values) {
            // If only one input value contains top elements, then the other input is the best approximation for the intersection.
            (true, false) => other.clone(),
            (false, true) => self.clone(),
            // Else we can compute the intersection field-wise.
            (true, true) | (false, false) => {
                let relative_values =
                    intersect_relative_values(&self.relative_values, &other.relative_values);
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
        // If one domain contains relative values and the other absolute values,
        // then we have to assume that the relative values could represent any of the absolute values.
        if let (true, Some(absolute_val)) = (self.relative_values.len() > 0, &other.absolute_value) {
            result = result.merge(&absolute_val.clone().into());
        }
        if let (Some(absolute_val), true) = (&self.absolute_value, other.relative_values.len() > 0) {
            result = result.merge(&absolute_val.clone().into());
        }

        if result.is_empty() {
            Err(anyhow!("Domain is empty."))
        } else {
            Ok(result)
        }
    }

    fn without_widening_hints(mut self) -> Self {
        for offset in self.relative_values.values_mut() {
            *offset = offset.clone().without_widening_hints();
        }
        self.absolute_value = self.absolute_value.map(|val| val.without_widening_hints());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{abstract_domain::*, variable};

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(variable!(format!("{}:8", name))),
        )
    }

    #[test]
    fn intersect() {
        // Element-wise intersection
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), IntervalDomain::mock(1, 1));
        targets.insert(new_id("Rbx"), IntervalDomain::mock(1, 10));
        let data_left = DataDomain::mock_from_target_map(targets);
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), IntervalDomain::mock(3, 3));
        targets.insert(new_id("Rbx"), IntervalDomain::mock(5, 15));
        targets.insert(new_id("Rcx"), IntervalDomain::mock(1, 1));
        let data_right = DataDomain::mock_from_target_map(targets);
        let intersection = data_left.intersect(&data_right).unwrap();
        assert_eq!(intersection.relative_values.len(), 1);
        assert_eq!(
            *intersection.relative_values.get(&new_id("Rbx")).unwrap(),
            IntervalDomain::mock(5, 10)
        );
        assert_eq!(intersection.absolute_value.is_none(), true);
        assert_eq!(intersection.contains_top_values, false);

        // Intersection when one side contains relative values and the other absolute values
        let mut targets = BTreeMap::new();
        targets.insert(new_id("Rax"), IntervalDomain::mock(1, 1));
        targets.insert(new_id("Rbx"), IntervalDomain::mock(1, 10));
        let data_left = DataDomain::mock_from_target_map(targets);
        let data_right = DataDomain::from(IntervalDomain::mock(10, 20));
        let intersection = data_left.clone().intersect(&data_right).unwrap();
        assert_eq!(intersection.relative_values.len(), 0);
        assert_eq!(
            intersection.absolute_value,
            Some(IntervalDomain::mock(10, 20))
        );
        assert_eq!(intersection.contains_top_values, false);

        // Intersection where exactly one side contains top elements
        let data_with_top = DataDomain::new_top(ByteSize::new(8));
        let intersection = data_left.clone().intersect(&data_with_top).unwrap();
        assert_eq!(intersection, data_left);

        // Empty intersection
        // NOTE: The checked behavior may actually be unsound depending on the use-case of the domain:
        // Two different relative values may be allowed to represent the same object/number.
        let data_left = DataDomain::from_target(new_id("RAX"), IntervalDomain::mock(0, 5));
        let data_right = DataDomain::from_target(new_id("RBX"), IntervalDomain::mock(0, 5));
        assert!(data_left.intersect(&data_right).is_err());
    }
}
