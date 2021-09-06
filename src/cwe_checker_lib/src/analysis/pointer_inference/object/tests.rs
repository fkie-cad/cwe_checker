use super::*;

fn new_abstract_object() -> AbstractObject {
    let inner = Inner {
        pointer_targets: BTreeSet::new(),
        is_unique: true,
        state: ObjectState::Alive,
        type_: Some(ObjectType::Heap),
        memory: MemRegion::new(ByteSize::new(8)),
        lower_index_bound: Bitvector::from_u64(0).into(),
        upper_index_bound: Bitvector::from_u64(99).into(),
    };
    inner.into()
}

fn new_data(number: i64) -> Data {
    bv(number).into()
}

fn bv(number: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(number))
}

fn new_id(tid: &str, reg_name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new(tid),
        AbstractLocation::Register(reg_name.into(), ByteSize::new(8)),
    )
}

#[test]
fn abstract_object() {
    let mut object = new_abstract_object();
    let three = new_data(3);
    let offset = bv(-15);
    object.set_value(three, &offset).unwrap();
    assert_eq!(
        object.get_value(Bitvector::from_i64(-16), ByteSize::new(8)),
        Data::new_top(ByteSize::new(8))
    );
    assert_eq!(
        object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
        new_data(3)
    );
    object.set_value(new_data(4), &bv(-12)).unwrap();
    assert_eq!(
        object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
        Data::new_top(ByteSize::new(8))
    );
    object.merge_value(new_data(23), &bv(-12));
    assert_eq!(
        object.get_value(Bitvector::from_i64(-12), ByteSize::new(8)),
        IntervalDomain::mock(4, 23).with_stride(19).into()
    );

    let mut other_object = new_abstract_object();
    object.set_value(new_data(0), &bv(0)).unwrap();
    other_object.set_value(new_data(0), &bv(0)).unwrap();
    let merged_object = object.merge(&other_object);
    assert_eq!(
        merged_object
            .get_value(Bitvector::from_i64(-12), ByteSize::new(8))
            .get_absolute_value(),
        Some(&IntervalDomain::mock(4, 23).with_stride(19).into())
    );
    assert!(merged_object
        .get_value(Bitvector::from_i64(-12), ByteSize::new(8))
        .contains_top());
    assert_eq!(
        merged_object.get_value(Bitvector::from_i64(0), ByteSize::new(8)),
        new_data(0)
    );
}

#[test]
fn replace_id() {
    use std::collections::BTreeMap;
    let mut object = new_abstract_object();
    let mut target_map = BTreeMap::new();
    target_map.insert(new_id("time_1", "RAX"), bv(20));
    target_map.insert(new_id("time_234", "RAX"), bv(30));
    target_map.insert(new_id("time_1", "RBX"), bv(40));
    let pointer = DataDomain::mock_from_target_map(target_map.clone());
    object.set_value(pointer, &bv(-15)).unwrap();
    assert_eq!(object.get_referenced_ids_overapproximation().len(), 3);

    object.replace_abstract_id(
        &new_id("time_1", "RAX"),
        &new_id("time_234", "RAX"),
        &bv(10),
    );
    target_map.remove(&new_id("time_1", "RAX"));
    let modified_pointer = DataDomain::mock_from_target_map(target_map);
    assert_eq!(
        object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
        modified_pointer
    );

    object.replace_abstract_id(
        &new_id("time_1", "RBX"),
        &new_id("time_234", "RBX"),
        &bv(10),
    );
    let mut target_map = BTreeMap::new();
    target_map.insert(new_id("time_234", "RAX"), bv(30));
    target_map.insert(new_id("time_234", "RBX"), bv(50));
    let modified_pointer = DataDomain::mock_from_target_map(target_map);
    assert_eq!(
        object.get_value(Bitvector::from_i64(-15), ByteSize::new(8)),
        modified_pointer
    );
}

#[test]
fn remove_ids() {
    use std::collections::BTreeMap;
    let mut object = new_abstract_object();
    let mut target_map = BTreeMap::new();
    target_map.insert(new_id("time_1", "RAX"), bv(20));
    target_map.insert(new_id("time_234", "RAX"), bv(30));
    target_map.insert(new_id("time_1", "RBX"), bv(40));
    let pointer = DataDomain::mock_from_target_map(target_map.clone());
    object.set_value(pointer, &bv(-15)).unwrap();
    assert_eq!(object.get_referenced_ids_overapproximation().len(), 3);

    let ids_to_remove = vec![new_id("time_1", "RAX"), new_id("time_23", "RBX")]
        .into_iter()
        .collect();
    object.remove_ids(&ids_to_remove);
    assert_eq!(
        object.get_referenced_ids_overapproximation(),
        &vec![new_id("time_234", "RAX"), new_id("time_1", "RBX")]
            .into_iter()
            .collect()
    );
}

#[test]
fn access_contained_in_bounds() {
    let object = new_abstract_object();
    assert!(object.access_contained_in_bounds(&IntervalDomain::mock(0, 99), ByteSize::new(1)));
    assert!(!object.access_contained_in_bounds(&IntervalDomain::mock(-1, -1), ByteSize::new(8)));
    assert!(object.access_contained_in_bounds(&IntervalDomain::mock(92, 92), ByteSize::new(8)));
    assert!(!object.access_contained_in_bounds(&IntervalDomain::mock(93, 93), ByteSize::new(8)));
}
