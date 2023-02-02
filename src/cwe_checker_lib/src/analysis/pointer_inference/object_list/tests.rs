use crate::intermediate_representation::*;
use crate::variable;

use super::super::ValueDomain;
use super::*;

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new("time0"),
        AbstractLocation::Register(variable!(format!("{name}:8"))),
    )
}

fn new_global_id() -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new("time0"),
        AbstractLocation::GlobalAddress {
            address: 0,
            size: ByteSize::new(8),
        },
    )
}

#[test]
fn abstract_object_list() {
    // A new object list has 2 memory objects.
    let mut obj_list = AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
    assert_eq!(obj_list.objects.len(), 2);
    // Test writing to and reading from the stack object
    let stack_pointer = DataDomain::from_target(new_id("RSP".into()), bv(8));
    obj_list
        .set_value(stack_pointer.clone(), bv(42).into())
        .unwrap();
    assert_eq!(
        obj_list.get_value(&stack_pointer, ByteSize::new(8)),
        bv(42).into()
    );
    // Test writing to and reading from the global memory object
    let global_pointer = DataDomain::from_target(new_global_id(), bv(1000));
    obj_list
        .set_value(global_pointer.clone(), bv(13).into())
        .unwrap();
    assert_eq!(
        obj_list.get_value(&global_pointer, ByteSize::new(8)),
        bv(13).into()
    );

    let mut other_obj_list =
        AbstractObjectList::from_stack_id(new_id("RSP".into()), ByteSize::new(8));
    let second_pointer = DataDomain::from_target(new_id("RSP".into()), bv(-8));
    other_obj_list
        .set_value(stack_pointer.clone(), bv(42).into())
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
        ByteSize::new(8),
        Some(ObjectType::Heap),
    );
    let heap_pointer = DataDomain::from_target(new_id("RAX".into()), bv(8));
    other_obj_list
        .set_value(heap_pointer.clone(), bv(3).into())
        .unwrap();

    let mut merged = obj_list.merge(&other_obj_list);
    assert_eq!(
        merged.get_value(&stack_pointer, ByteSize::new(8)),
        bv(42).into()
    );

    assert!(merged
        .get_value(&second_pointer, ByteSize::new(8))
        .contains_top());
    assert_eq!(
        merged.get_value(&heap_pointer, ByteSize::new(8)),
        bv(3).into()
    );
    assert_eq!(merged.objects.len(), 3);

    merged
        .set_value(stack_pointer.merge(&heap_pointer), bv(3).into())
        .unwrap();
    assert_eq!(
        merged.get_value(&stack_pointer, ByteSize::new(8)),
        IntervalDomain::mock(3, 42).with_stride(39).into()
    );
    assert_eq!(
        merged.get_value(&heap_pointer, ByteSize::new(8)),
        bv(3).into()
    );
    assert_eq!(merged.objects.len(), 3);

    other_obj_list
        .set_value(stack_pointer.clone(), heap_pointer.clone())
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

    let mut ids_to_keep = BTreeSet::new();
    ids_to_keep.insert(new_id("RAX".into()));
    other_obj_list.remove_unused_objects(&ids_to_keep);
    assert_eq!(other_obj_list.objects.len(), 1);
    assert_eq!(
        other_obj_list.objects.iter().next().unwrap().0,
        &new_id("RAX".into())
    );
}
