use super::*;
use crate::abstract_domain::DataDomain;
use crate::abstract_domain::IntervalDomain;
use crate::abstract_domain::RegisterDomain;
use crate::bitvec;
use crate::intermediate_representation::*;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, PartialOrd, Ord)]
struct MockDomain(i64, ByteSize);

impl AbstractDomain for MockDomain {
    fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.1, other.1);
        if self == other {
            self.clone()
        } else {
            self.top()
        }
    }

    fn is_top(&self) -> bool {
        self == &self.top()
    }
}

impl SizedDomain for MockDomain {
    fn bytesize(&self) -> ByteSize {
        self.1
    }

    fn new_top(bytesize: ByteSize) -> MockDomain {
        MockDomain(0, bytesize)
    }
}

impl HasTop for MockDomain {
    fn top(&self) -> Self {
        Self::new_top(self.1)
    }
}

impl RegisterDomain for MockDomain {
    fn bin_op(&self, _op: BinOpType, _rhs: &Self) -> Self {
        Self::new_top(self.1)
    }

    fn un_op(&self, _op: UnOpType) -> Self {
        Self::new_top(self.1)
    }

    fn cast(&self, _kind: CastOpType, width: ByteSize) -> Self {
        Self::new_top(width)
    }

    fn subpiece(&self, _low_byte: ByteSize, size: ByteSize) -> Self {
        Self::new_top(size)
    }
}

fn mock(val: i64, bytesize: impl Into<ByteSize>) -> MockDomain {
    MockDomain(val, bytesize.into())
}

#[test]
fn mem_region() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(5, 3u64), bitvec!("5:8"));
    assert_eq!(
        region.get(bitvec!("5:8"), ByteSize::from(3u64)),
        mock(5, 3u64)
    );
    region.add(mock(7, 2u64), bitvec!("8:8"));
    assert_eq!(
        region.get(bitvec!("8:8"), ByteSize::from(2u64)),
        mock(7, 2u64)
    );
    assert_eq!(
        region.get(bitvec!("5:8"), ByteSize::from(3u64)),
        mock(5, 3u64)
    );
    assert_eq!(
        region.get(bitvec!("5:8"), ByteSize::from(2u64)),
        MockDomain::new_top(ByteSize::new(2))
    );
    region.add(mock(9, 2u64), bitvec!("6:8"));
    assert_eq!(
        region.get(bitvec!("6:8"), ByteSize::from(2u64)),
        mock(9, 2u64)
    );
    assert_eq!(
        region.get(bitvec!("5:8"), ByteSize::from(3u64)),
        MockDomain::new_top(ByteSize::new(3))
    );
    assert_eq!(
        region.get(bitvec!("8:8"), ByteSize::from(2u64)),
        mock(7, 2u64)
    );
    region.add(mock(9, 11u64), bitvec!("-3:8"));
    assert_eq!(
        region.get(bitvec!("-3:8"), ByteSize::from(11u64)),
        mock(9, 11u64)
    );
    assert_eq!(
        region.get(bitvec!("6:8"), ByteSize::from(2u64)),
        MockDomain::new_top(ByteSize::new(2))
    );
    assert_eq!(
        region.get(bitvec!("8:8"), ByteSize::from(2u64)),
        mock(7, 2u64)
    );

    let mut other_region = MemRegion::new(ByteSize::from(8u64));
    other_region.add(mock(7, 2u64), bitvec!("8:8"));
    assert!(region != other_region);
    let merged_region = region.merge(&other_region);
    assert_eq!(
        merged_region.get(bitvec!("8:8"), ByteSize::from(2u64)),
        mock(7, 2u64)
    );
    assert_eq!(
        merged_region.get(bitvec!("-3:8"), ByteSize::from(11u64)),
        MockDomain::new_top(ByteSize::from(11u64))
    );
    other_region.add(mock(9, 11u64), bitvec!("-3:8"));
    assert_eq!(region, other_region);
}

#[test]
fn merge_test() {
    let data: fn(u64) -> DataDomain<IntervalDomain> =
        |val| DataDomain::from(bitvec!(format!("{}:8", val)));
    let mut region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    region.add(data(0), bitvec!("0:8"));
    region.add(data(8), bitvec!("8:8"));
    region.add(data(22), bitvec!("32:8"));
    region.add(data(42), bitvec!("50:8"));
    region.add(data(70), bitvec!("70:8"));
    let mut other_region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    other_region.add(data(1), bitvec!("0:8"));
    other_region.add(data(15), bitvec!("15:8"));
    other_region.add(data(26), bitvec!("25:8"));
    other_region.add(data(42), bitvec!("58:8"));
    other_region.add(bitvec!("70:1").into(), bitvec!("70:8"));
    let merged_region = region.merge(&&other_region);
    // Merge elements at target address.
    assert_eq!(
        merged_region.get_unsized(bitvec!("0:8")),
        Some(IntervalDomain::mock(0, 1).into())
    );
    // Overlapping elements are not added to the merged memory region.
    assert_eq!(merged_region.get_unsized(bitvec!("8:8")), None);
    assert_eq!(merged_region.get_unsized(bitvec!("15:8")), None);
    assert_eq!(merged_region.get_unsized(bitvec!("25:8")), None);
    assert_eq!(merged_region.get_unsized(bitvec!("32:8")), None);
    // Elements only contained in one region are merged with `Top`.
    let mut elem_plus_top: DataDomain<IntervalDomain> = bitvec!("42:8").into();
    elem_plus_top.set_contains_top_flag();
    assert!(!elem_plus_top.is_top());
    assert_eq!(
        merged_region.get_unsized(bitvec!("50:8")),
        Some(elem_plus_top.clone())
    );
    assert_eq!(
        merged_region.get_unsized(bitvec!("58:8")),
        Some(elem_plus_top)
    );
    // Elements with differing bytesizes are not added to the merged domain.
    assert_eq!(merged_region.get_unsized(bitvec!("70:8")), None);
    // Check that no other unexpected elements are contained in the merged region.
    assert_eq!(merged_region.values().len(), 3);
}

#[test]
fn do_not_save_top_elements() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(MockDomain::new_top(ByteSize::from(4u64)), bitvec!("5:8"));
    assert_eq!(region.values().len(), 0);

    let mut other_region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(5, 4u64), bitvec!("5:8"));
    other_region.add(mock(7, 4u64), bitvec!("5:8"));
    let merged_region = region.merge(&other_region);
    assert_eq!(region.values().len(), 1);
    assert_eq!(other_region.values().len(), 1);
    assert_eq!(merged_region.values().len(), 0);
}

#[test]
fn value_removals() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(1, 8u64), bitvec!("0:8"));
    region.add(mock(2, 8u64), bitvec!("8:8"));
    region.add(mock(3, 8u64), bitvec!("16:8"));
    region.add(mock(4, 8u64), bitvec!("24:8"));
    region.add(mock(5, 8u64), bitvec!("32:8"));

    assert_eq!(region.values().len(), 5);
    region.remove(bitvec!("2:8"), bitvec!("3:8"));
    assert_eq!(region.values().len(), 4);
    region.remove(bitvec!("7:8"), bitvec!("1:8"));
    assert_eq!(region.values().len(), 4);
    region.remove(bitvec!("7:8"), bitvec!("2:8"));
    assert_eq!(region.values().len(), 3);

    region.clear_interval(15, 1);
    assert_eq!(region.values().len(), 3);
    region.clear_interval(15, 3);
    assert_eq!(region.values().len(), 2);

    for val in region.values_mut() {
        if *val == mock(5, 8u64) {
            *val = mock(0, 8u64); // This is a *Top* element
        }
    }
    region.clear_top_values();
    assert_eq!(region.values().len(), 1);
    assert_eq!(
        region.get(bitvec!("24:8"), ByteSize::from(8u64)),
        mock(4, 8u64)
    );
}

#[test]
fn merge_writes_with_top() {
    let data: DataDomain<IntervalDomain> = DataDomain::from(bitvec!("0:8"));
    let mut data_with_top = data.clone();
    data_with_top.set_contains_top_flag();
    let mut region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    // Test `merge_write_top` method.
    region.add(data.clone(), bitvec!("0:8"));
    region.merge_write_top(bitvec!("0:8"), ByteSize::new(8));
    assert_eq!(
        region.get_unsized(bitvec!("0:8")),
        Some(data_with_top.clone())
    );
    // `merge_write_top` removes intersecting values if position or size do not match.
    region.add(data.clone(), bitvec!("8:8"));
    region.merge_write_top(bitvec!("5:8"), ByteSize::new(8));
    assert!(region.inner.values.is_empty());
    // Test `mark_interval_values_as_top` method.
    region.add(data.clone(), bitvec!("0:8"));
    region.add(data.clone(), bitvec!("8:8"));
    region.add(data.clone(), bitvec!("16:8"));
    region.mark_interval_values_as_top(9, 16, ByteSize::new(1));
    assert_eq!(region.get_unsized(bitvec!("0:8")), Some(data));
    assert_eq!(
        region.get_unsized(bitvec!("8:8")),
        Some(data_with_top.clone())
    );
    assert_eq!(
        region.get_unsized(bitvec!("16:8")),
        Some(data_with_top.clone())
    );
}
