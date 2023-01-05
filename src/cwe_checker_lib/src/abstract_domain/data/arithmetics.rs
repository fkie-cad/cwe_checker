use super::*;

impl<T: RegisterDomain> DataDomain<T> {
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

    /// If both `self` and `rhs` are pointers to a unique (but not necessarily the same) target,
    /// compute `self - rhs`.
    /// Return `None` otherwise.
    fn compute_sub_if_offset_through_pointer_subtraction(&self, rhs: &Self) -> Option<Self> {
        if let (Some((lhs_id, lhs_offset)), Some((rhs_id, rhs_offset))) =
            (self.get_if_unique_target(), rhs.get_if_unique_target())
        {
            // Compute an offset by subtracting pointers
            if lhs_id == rhs_id {
                Some(DataDomain {
                    size: self.bytesize(),
                    relative_values: BTreeMap::new(),
                    absolute_value: Some(lhs_offset.bin_op(BinOpType::IntSub, rhs_offset)),
                    contains_top_values: false,
                })
            } else {
                // `self` and `rhs` are relative different abstract IDs.
                Some(DataDomain {
                    size: self.bytesize(),
                    relative_values: BTreeMap::from_iter([
                        (lhs_id.clone(), T::new_top(self.bytesize())),
                        (rhs_id.clone(), T::new_top(self.bytesize())),
                    ]),
                    absolute_value: Some(T::new_top(self.bytesize())),
                    contains_top_values: false,
                })
            }
        } else {
            None
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
        } else if let Some(result) = self.compute_sub_if_offset_through_pointer_subtraction(rhs) {
            result
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
    fn pointer_sub() {
        use BinOpType::*;
        let pointer1 = new_pointer("Rax".into(), 10);
        let pointer2 = new_pointer("Rax".into(), 4);
        // Pointer difference computes offset (i.e. an absolute value)
        assert_eq!(pointer1.bin_op(IntSub, &pointer2), bv(6).into());

        // It is unknown whether the difference is an offset or not.
        let other_pointer = new_pointer("Rbx".into(), 4);
        let diff = pointer1.bin_op(IntSub, &&other_pointer);
        assert_eq!(diff.relative_values.len(), 2);
        assert_eq!(
            *diff.relative_values.get(&new_id("Rax")).unwrap(),
            BitvectorDomain::new_top(ByteSize::new(8))
        );
        assert_eq!(
            *diff.relative_values.get(&new_id("Rbx")).unwrap(),
            BitvectorDomain::new_top(ByteSize::new(8))
        );
        assert_eq!(
            diff.absolute_value,
            Some(BitvectorDomain::new_top(ByteSize::new(8)))
        );
        assert_eq!(diff.contains_top_values, false);
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
            BitvectorDomain::Value(bitvec!("3:4")).into()
        );

        assert_eq!(
            data.cast(CastOpType::IntSExt, ByteSize::new(16)).bytesize(),
            ByteSize::new(16)
        );

        let one: Data = BitvectorDomain::Value(bitvec!("1:4")).into();
        let two: Data = BitvectorDomain::Value(bitvec!("2:4")).into();
        let concat = new_value((1 << 32) + 2);
        assert_eq!(one.bin_op(Piece, &two), concat);
    }

    #[test]
    fn float_nan_bytesize() {
        let top_value: DataDomain<BitvectorDomain> = DataDomain::new_top(ByteSize::new(8));
        let result = top_value.un_op(UnOpType::FloatNaN);
        assert!(result.is_top());
        assert_eq!(result.bytesize(), ByteSize::new(1));
    }
}
