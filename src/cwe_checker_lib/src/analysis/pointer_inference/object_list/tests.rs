use crate::intermediate_representation::Variable;

use super::*;

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new("time0"),
        AbstractLocation::Register(Variable::mock(name, ByteSize::new(8))),
    )
}

#[test]
fn abstract_object_list() {
    let mut obj_list = AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
    assert_eq!(obj_list.objects.len(), 1);
    assert_eq!(obj_list.objects.values().next().unwrap().1, bv(0));

    let pointer = DataDomain::from_target(new_id("RSP".into()), bv(8));
    obj_list.set_value(pointer.clone(), bv(42).into()).unwrap();
    assert_eq!(
        obj_list.get_value(&pointer, ByteSize::new(8)),
        bv(42).into()
    );

    let mut other_obj_list =
        AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
    let second_pointer = DataDomain::from_target(new_id("RSP".into()), bv(-8));
    other_obj_list
        .set_value(pointer.clone(), bv(42).into())
        .unwrap();
    other_obj_list
        .set_value(second_pointer.clone(), bv(35).into())
        .unwrap();
    assert_eq!(
        other_obj_list.get_value(&second_pointer, ByteSize::new(8)),
        bv(35).into()
    );

    other_obj_list.add_abstract_object(
        new_id("RAX".into()),
        bv(0),
        ObjectType::Heap,
        ByteSize::new(8),
    );
    let heap_pointer = DataDomain::from_target(new_id("RAX".into()), bv(8));
    other_obj_list
        .set_value(heap_pointer.clone(), bv(3).into())
        .unwrap();

    let mut merged = obj_list.merge(&other_obj_list);
    assert_eq!(merged.get_value(&pointer, ByteSize::new(8)), bv(42).into());

    assert!(merged
        .get_value(&second_pointer, ByteSize::new(8))
        .contains_top());
    assert_eq!(
        merged.get_value(&heap_pointer, ByteSize::new(8)),
        bv(3).into()
    );
    assert_eq!(merged.objects.len(), 2);

    merged
        .set_value(pointer.merge(&heap_pointer), bv(3).into())
        .unwrap();
    assert_eq!(
        merged.get_value(&pointer, ByteSize::new(8)),
        IntervalDomain::mock(3, 42).with_stride(39).into()
    );
    assert_eq!(
        merged.get_value(&heap_pointer, ByteSize::new(8)),
        bv(3).into()
    );
    assert_eq!(merged.objects.len(), 2);

    other_obj_list
        .set_value(pointer.clone(), heap_pointer.clone())
        .unwrap();
    assert_eq!(
        other_obj_list
            .get_referenced_ids_overapproximation(&new_id("RSP".into()))
            .len(),
        1
    );
    assert_eq!(
        *other_obj_list
            .get_referenced_ids_overapproximation(&new_id("RSP".into()))
            .iter()
            .next()
            .unwrap(),
        new_id("RAX".into())
    );

    let modified_heap_pointer = DataDomain::from_target(new_id("ID2".into()), bv(8));
    other_obj_list.replace_abstract_id(&new_id("RAX".into()), &new_id("ID2".into()), &bv(0));
    assert_eq!(
        other_obj_list.get_value(&pointer, ByteSize::new(8)),
        modified_heap_pointer.clone()
    );
    assert_eq!(other_obj_list.objects.get(&new_id("RAX".into())), None);
    assert!(matches!(
        other_obj_list.objects.get(&new_id("ID2".into())),
        Some(_)
    ));

    let mut ids_to_keep = BTreeSet::new();
    ids_to_keep.insert(new_id("ID2".into()));
    other_obj_list.remove_unused_objects(&ids_to_keep);
    assert_eq!(other_obj_list.objects.len(), 1);
    assert_eq!(
        other_obj_list.objects.iter().next().unwrap().0,
        &new_id("ID2".into())
    );

    assert_eq!(
        other_obj_list
            .objects
            .values()
            .next()
            .unwrap()
            .0
            .get_state(),
        crate::analysis::pointer_inference::object::ObjectState::Alive
    );
    other_obj_list
        .mark_mem_object_as_freed(&modified_heap_pointer)
        .unwrap();
    assert_eq!(
        other_obj_list
            .objects
            .values()
            .next()
            .unwrap()
            .0
            .get_state(),
        crate::analysis::pointer_inference::object::ObjectState::Dangling
    );
}

#[test]
fn append_unknown_objects_test() {
    let mut obj_list = AbstractObjectList::from_stack_id(new_id("stack"), ByteSize::new(8));

    let mut other_obj_list = AbstractObjectList::from_stack_id(new_id("stack"), ByteSize::new(8));
    other_obj_list.add_abstract_object(
        new_id("heap_obj"),
        bv(0).into(),
        ObjectType::Heap,
        ByteSize::new(8),
    );

    obj_list.append_unknown_objects(&other_obj_list);
    assert_eq!(obj_list.objects.len(), 2);
    assert!(obj_list.objects.get(&new_id("stack")).is_some());
    assert!(obj_list.objects.get(&new_id("heap_obj")).is_some());
}
