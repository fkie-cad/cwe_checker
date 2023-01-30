use super::*;

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

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::{abstract_domain::*, bitvec, variable};

    type Data = DataDomain<BitvectorDomain>;

    fn bv(value: i64) -> BitvectorDomain {
        BitvectorDomain::Value(bitvec!(format!("{}:8", value)))
    }

    fn new_id(name: &str) -> AbstractIdentifier {
        AbstractIdentifier::new(
            Tid::new("time0"),
            AbstractLocation::Register(variable!(format!("{}:8", name))),
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
}
