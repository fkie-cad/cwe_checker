use super::*;
use crate::abstract_domain::DataDomain;
use crate::abstract_domain::IntervalDomain;
use crate::abstract_domain::RegisterDomain;
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

fn bv(val: i64) -> Bitvector {
    Bitvector::from_i64(val)
}

#[test]
fn mem_region() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(5, 3u64), bv(5));
    assert_eq!(region.get(bv(5), ByteSize::from(3u64)), mock(5, 3u64));
    region.add(mock(7, 2u64), bv(8));
    assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));
    assert_eq!(region.get(bv(5), ByteSize::from(3u64)), mock(5, 3u64));
    assert_eq!(
        region.get(bv(5), ByteSize::from(2u64)),
        MockDomain::new_top(ByteSize::new(2))
    );
    region.add(mock(9, 2u64), bv(6));
    assert_eq!(region.get(bv(6), ByteSize::from(2u64)), mock(9, 2u64));
    assert_eq!(
        region.get(bv(5), ByteSize::from(3u64)),
        MockDomain::new_top(ByteSize::new(3))
    );
    assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));
    region.add(mock(9, 11u64), bv(-3));
    assert_eq!(region.get(bv(-3), ByteSize::from(11u64)), mock(9, 11u64));
    assert_eq!(
        region.get(bv(6), ByteSize::from(2u64)),
        MockDomain::new_top(ByteSize::new(2))
    );
    assert_eq!(region.get(bv(8), ByteSize::from(2u64)), mock(7, 2u64));

    let mut other_region = MemRegion::new(ByteSize::from(8u64));
    other_region.add(mock(7, 2u64), bv(8));
    assert!(region != other_region);
    let merged_region = region.merge(&other_region);
    assert_eq!(
        merged_region.get(bv(8), ByteSize::from(2u64)),
        mock(7, 2u64)
    );
    assert_eq!(
        merged_region.get(bv(-3), ByteSize::from(11u64)),
        MockDomain::new_top(ByteSize::from(11u64))
    );
    other_region.add(mock(9, 11u64), bv(-3));
    assert_eq!(region, other_region);
}

#[test]
fn merge_test() {
    let data: fn(u64) -> DataDomain<IntervalDomain> =
        |val| DataDomain::from(Bitvector::from_u64(val));
    let mut region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    region.add(data(0), Bitvector::from_u64(0));
    region.add(data(8), Bitvector::from_u64(8));
    region.add(data(22), Bitvector::from_u64(32));
    region.add(data(42), Bitvector::from_u64(50));
    region.add(data(70), Bitvector::from_u64(70));
    let mut other_region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    other_region.add(data(1), Bitvector::from_u64(0));
    other_region.add(data(15), Bitvector::from_u64(15));
    other_region.add(data(26), Bitvector::from_u64(25));
    other_region.add(data(42), Bitvector::from_u64(58));
    other_region.add(Bitvector::from_u8(70).into(), Bitvector::from_u64(70));
    let merged_region = region.merge(&&other_region);
    // Merge elements at target address.
    assert_eq!(
        merged_region.get_unsized(Bitvector::from_u64(0)),
        Some(IntervalDomain::mock(0, 1).into())
    );
    // Overlapping elements are not added to the merged memory region.
    assert_eq!(merged_region.get_unsized(Bitvector::from_u64(8)), None);
    assert_eq!(merged_region.get_unsized(Bitvector::from_u64(15)), None);
    assert_eq!(merged_region.get_unsized(Bitvector::from_u64(25)), None);
    assert_eq!(merged_region.get_unsized(Bitvector::from_u64(32)), None);
    // Elements only contained in one region are merged with `Top`.
    let mut elem_plus_top: DataDomain<IntervalDomain> = Bitvector::from_u64(42).into();
    elem_plus_top.set_contains_top_flag();
    assert!(!elem_plus_top.is_top());
    assert_eq!(
        merged_region.get_unsized(Bitvector::from_u64(50)),
        Some(elem_plus_top.clone())
    );
    assert_eq!(
        merged_region.get_unsized(Bitvector::from_u64(58)),
        Some(elem_plus_top)
    );
    // Elements with differing bytesizes are not added to the merged domain.
    assert_eq!(merged_region.get_unsized(Bitvector::from_u64(70)), None);
    // Check that no other unexpected elements are contained in the merged region.
    assert_eq!(merged_region.values().len(), 3);
}

#[test]
fn do_not_save_top_elements() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(MockDomain::new_top(ByteSize::from(4u64)), bv(5));
    assert_eq!(region.values().len(), 0);

    let mut other_region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(5, 4u64), bv(5));
    other_region.add(mock(7, 4u64), bv(5));
    let merged_region = region.merge(&other_region);
    assert_eq!(region.values().len(), 1);
    assert_eq!(other_region.values().len(), 1);
    assert_eq!(merged_region.values().len(), 0);
}

#[test]
fn value_removals() {
    let mut region: MemRegion<MockDomain> = MemRegion::new(ByteSize::from(8u64));
    region.add(mock(1, 8u64), bv(0));
    region.add(mock(2, 8u64), bv(8));
    region.add(mock(3, 8u64), bv(16));
    region.add(mock(4, 8u64), bv(24));
    region.add(mock(5, 8u64), bv(32));

    assert_eq!(region.values().len(), 5);
    region.remove(bv(2), bv(3));
    assert_eq!(region.values().len(), 4);
    region.remove(bv(7), bv(1));
    assert_eq!(region.values().len(), 4);
    region.remove(bv(7), bv(2));
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
    assert_eq!(region.get(bv(24), ByteSize::from(8u64)), mock(4, 8u64));
}

#[test]
fn merge_writes_with_top() {
    let data: DataDomain<IntervalDomain> = DataDomain::from(Bitvector::from_u64(0));
    let mut data_with_top = data.clone();
    data_with_top.set_contains_top_flag();
    let mut region: MemRegion<DataDomain<IntervalDomain>> = MemRegion::new(ByteSize::new(8));
    // Test `merge_write_top` method.
    region.add(data.clone(), bv(0));
    region.merge_write_top(bv(0), ByteSize::new(8));
    assert_eq!(region.get_unsized(bv(0)), Some(data_with_top.clone()));
    // `merge_write_top` removes intersecting values if position or size do not match.
    region.add(data.clone(), bv(8));
    region.merge_write_top(bv(5), ByteSize::new(8));
    assert!(region.inner.values.is_empty());
    // Test `mark_interval_values_as_top` method.
    region.add(data.clone(), bv(0));
    region.add(data.clone(), bv(8));
    region.add(data.clone(), bv(16));
    region.mark_interval_values_as_top(9, 16, ByteSize::new(1));
    assert_eq!(region.get_unsized(bv(0)), Some(data));
    assert_eq!(region.get_unsized(bv(8)), Some(data_with_top.clone()));
    assert_eq!(region.get_unsized(bv(16)), Some(data_with_top.clone()));
}
