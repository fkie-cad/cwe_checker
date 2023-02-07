use super::*;
use crate::{intermediate_representation::*, variable};
use std::collections::BTreeMap;

fn new_abstract_object() -> AbstractObject {
    let inner = Inner {
        pointer_targets: BTreeSet::new(),
        is_unique: true,
        type_: Some(ObjectType::Heap),
        memory: MemRegion::new(ByteSize::new(8)),
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
        AbstractLocation::Register(variable!(format!("{reg_name}:8"))),
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
fn overwrite_with() {
    let mut object = new_abstract_object();
    object.set_value(bv(1).into(), &bv(0).into()).unwrap();
    object.set_value(bv(2).into(), &bv(8).into()).unwrap();
    let mut other_object = new_abstract_object();
    other_object.set_value(bv(3).into(), &bv(0).into()).unwrap();
    other_object.set_value(bv(4).into(), &bv(8).into()).unwrap();

    object.overwrite_with(&other_object, &bv(8).into());

    let mut expected_result = new_abstract_object();
    let mut data: Data = bv(1).into();
    data.set_contains_top_flag();
    expected_result.set_value(data, &bv(0).into()).unwrap();
    expected_result
        .set_value(bv(3).into(), &bv(8).into())
        .unwrap();
    expected_result
        .set_value(bv(4).into(), &bv(16).into())
        .unwrap();

    assert_eq!(object, expected_result);
}

#[test]
fn replace_ids() {
    let set_value = |object: &mut AbstractObject, tid: &str, register: &str, offset: i64| {
        object
            .set_value(
                Data::from_target(new_id(tid, register), bv(0).into()),
                &bv(offset).into(),
            )
            .unwrap();
    };
    let mut object = new_abstract_object();
    set_value(&mut object, "before", "RAX", 0);
    set_value(&mut object, "before", "RBX", 8);
    let mut replacement_map = BTreeMap::new();
    replacement_map.insert(
        new_id("before", "RAX"),
        Data::from_target(new_id("after", "RCX"), bv(0).into()),
    );
    let mut expected_result = new_abstract_object();
    set_value(&mut expected_result, "after", "RCX", 0);

    object.replace_ids(&replacement_map);
    assert_eq!(object, expected_result);
}
