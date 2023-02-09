use super::*;
use crate::{
    abstract_domain::{AbstractLocation, CharacterInclusionDomain},
    analysis::{
        pointer_inference::State as PiState,
        string_abstraction::tests::mock_project_with_intraprocedural_control_flow,
    },
    expr,
    intermediate_representation::*,
    variable,
};
use std::collections::BTreeSet;

impl<T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> State<T> {
    pub fn mock_with_default_pi_state(current_sub: Term<Sub>) -> Self {
        let pi_state = PointerInferenceState::new(
            &variable!("sp:4"),
            current_sub.tid.clone(),
            BTreeSet::new(),
        );
        State {
            unassigned_return_pointer: HashSet::new(),
            variable_to_pointer_map: HashMap::new(),
            stack_offset_to_pointer_map: HashMap::new(),
            stack_offset_to_string_map: HashMap::new(),
            heap_to_string_map: HashMap::new(),
            current_sub: Arc::new(Some(current_sub)),
            pointer_inference_state: Some(pi_state),
        }
    }

    pub fn mock_with_given_pi_state(current_sub: Term<Sub>, pi_state: PiState) -> Self {
        State {
            unassigned_return_pointer: HashSet::new(),
            variable_to_pointer_map: HashMap::new(),
            stack_offset_to_pointer_map: HashMap::new(),
            stack_offset_to_string_map: HashMap::new(),
            heap_to_string_map: HashMap::new(),
            current_sub: Arc::new(Some(current_sub)),
            pointer_inference_state: Some(pi_state),
        }
    }

    pub fn _get_unassigned_return_pointer(&self) -> &HashSet<DataDomain<IntervalDomain>> {
        &self.unassigned_return_pointer
    }
}

#[test]
fn test_delete_string_map_entries_if_no_pointer_targets_are_tracked() {
    let mut state: State<CharacterInclusionDomain> =
        State::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );
    let stack_pointer: DataDomain<IntervalDomain> = DataDomain::from_target(
        stack_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    let heap_id_1 = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
    );

    let heap_pointer_1: DataDomain<IntervalDomain> = DataDomain::from_target(
        heap_id_1.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    let heap_id_2 = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r6:4")).unwrap(),
    );

    let heap_pointer_2: DataDomain<IntervalDomain> = DataDomain::from_target(
        heap_id_2.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );

    let heap_id_3 = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r7:4")).unwrap(),
    );

    state
        .variable_to_pointer_map
        .insert(variable!("r0:4"), stack_pointer);
    state.stack_offset_to_pointer_map.insert(-8, heap_pointer_1);
    state.unassigned_return_pointer.insert(heap_pointer_2);

    state
        .stack_offset_to_string_map
        .insert(0, CharacterInclusionDomain::Top); // pointer tracked
    state
        .stack_offset_to_string_map
        .insert(4, CharacterInclusionDomain::Top); // will be deleted
    state
        .heap_to_string_map
        .insert(heap_id_1.clone(), CharacterInclusionDomain::Top); // pointer tracked
    state
        .heap_to_string_map
        .insert(heap_id_2.clone(), CharacterInclusionDomain::Top); // pointer tracked
    state
        .heap_to_string_map
        .insert(heap_id_3.clone(), CharacterInclusionDomain::Top); // will be deleted

    let new_state = state.delete_string_map_entries_if_no_pointer_targets_are_tracked();

    assert_eq!(
        new_state.stack_offset_to_string_map.get(&0),
        Some(&CharacterInclusionDomain::Top)
    );
    assert_eq!(new_state.stack_offset_to_string_map.get(&4), None);
    assert_eq!(
        new_state.heap_to_string_map.get(&heap_id_1),
        Some(&CharacterInclusionDomain::Top)
    );
    assert_eq!(
        new_state.heap_to_string_map.get(&heap_id_2),
        Some(&CharacterInclusionDomain::Top)
    );
    assert_eq!(new_state.heap_to_string_map.get(&heap_id_3), None);
}

#[test]
fn test_evaluate_constant() {
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let constant = Bitvector::from_i32(0x7000);
    let state: State<CharacterInclusionDomain> =
        State::mock_with_default_pi_state(Sub::mock("func"));

    let block_first_def_set: HashSet<(Tid, Tid)> = HashSet::new();

    assert_eq!(
        Some(DataDomain::from(Bitvector::from_i32(
            constant.clone().try_to_i32().unwrap()
        ))),
        state.evaluate_constant(&runtime_memory_image, &block_first_def_set, constant)
    );

    assert_eq!(
        None,
        state.evaluate_constant(
            &runtime_memory_image,
            &block_first_def_set,
            Bitvector::from_i32(0x1234)
        )
    );
}

#[test]
fn test_handle_assign_and_load() {
    let sub = Sub::mock("func");
    let mut state: State<CharacterInclusionDomain> = State::mock_with_default_pi_state(sub.clone());
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let output = variable!("r1:4");
    let constant_input = Expression::Const(Bitvector::from_str_radix(16, "7000").unwrap());
    let return_address_input = Expression::Const(Bitvector::from_str_radix(16, "14718").unwrap());
    let other_input = expr!("r6:4");

    let mut block_first_def_set: HashSet<(Tid, Tid)> = HashSet::new();
    let mut return_tid = Tid::new("14718");
    return_tid.address = "14718".to_string();
    block_first_def_set.insert((return_tid, sub.tid));

    let constant_data_domain = DataDomain::from(Bitvector::from_i64(0x7000));

    let mut pi_state = state.get_pointer_inference_state().unwrap().clone();
    pi_state.set_register(&output, constant_data_domain.clone());
    state.set_pointer_inference_state(Some(pi_state.clone()));

    // Test Case 1: Assign Def with constant input
    state.handle_assign_and_load(
        &output,
        &constant_input,
        &runtime_memory_image,
        &block_first_def_set,
        true,
    );
    assert_eq!(
        *state.variable_to_pointer_map.get(&output).unwrap(),
        constant_data_domain
    );
    state.set_all_maps_empty();

    // Test Case 1.1: Assign Def with constant input but no pi_state.
    state.set_pointer_inference_state(None);
    state.handle_assign_and_load(
        &output,
        &constant_input,
        &runtime_memory_image,
        &block_first_def_set,
        true,
    );
    assert_eq!(
        *state.variable_to_pointer_map.get(&output).unwrap(),
        constant_data_domain
    );
    state.set_all_maps_empty();

    // Test Case 1.2: Assign Def with constant input that is a return address
    state.handle_assign_and_load(
        &output,
        &return_address_input,
        &runtime_memory_image,
        &block_first_def_set,
        true,
    );
    assert!(state.variable_to_pointer_map.is_empty());

    // Test Case 2: Assign Def with other input
    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
    );

    let heap_pointer: DataDomain<IntervalDomain> = DataDomain::from_target(
        heap_id.clone(),
        Bitvector::zero(apint::BitWidth::from(4)).into(),
    );
    pi_state.set_register(&output, heap_pointer.clone());
    state.set_pointer_inference_state(Some(pi_state.clone()));
    state.unassigned_return_pointer.insert(heap_pointer.clone());

    state.handle_assign_and_load(
        &output,
        &other_input,
        &runtime_memory_image,
        &block_first_def_set,
        true,
    );

    assert_eq!(
        *state.variable_to_pointer_map.get(&output).unwrap(),
        heap_pointer
    );
    state.set_all_maps_empty();

    // Test Case 3: Load Def with constant input
    state.handle_assign_and_load(
        &output,
        &constant_input,
        &runtime_memory_image,
        &block_first_def_set,
        false,
    );

    // Test Case 4: Load Def with other input
    state.unassigned_return_pointer.insert(heap_pointer.clone());
    state.handle_assign_and_load(
        &output,
        &other_input,
        &runtime_memory_image,
        &block_first_def_set,
        false,
    );

    assert_eq!(
        *state.variable_to_pointer_map.get(&output).unwrap(),
        heap_pointer
    );
}

#[test]
fn test_add_pointer_to_variable_maps_if_tracked() {
    let output_var = variable!("r2:4");
    let origin_var = variable!("r5:4");
    let mut mock_state =
        State::<CharacterInclusionDomain>::mock_with_default_pi_state(Sub::mock("func"));
    let pi_state = mock_state.get_pointer_inference_state().unwrap().clone();

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
    );
    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );

    let mut source_pointer: DataDomain<IntervalDomain> =
        DataDomain::from_target(stack_id.clone(), Bitvector::from_i32(4).into());

    // Test Case 1: Pointer is tracked in unassigned pointer map.
    mock_state.add_unassigned_return_pointer(source_pointer.clone());
    assert!(mock_state.pointer_added_to_variable_maps(
        &pi_state,
        &output_var,
        source_pointer.clone()
    ));
    mock_state.set_all_maps_empty();

    // Test Case 2: Pointer is tracked in register to pointer map.
    mock_state.add_new_variable_to_pointer_entry(origin_var, source_pointer.clone());
    assert!(mock_state.pointer_added_to_variable_maps(
        &pi_state,
        &output_var,
        source_pointer.clone()
    ));
    assert_eq!(
        source_pointer,
        *mock_state
            .get_variable_to_pointer_map()
            .get(&output_var)
            .unwrap()
    );
    mock_state.set_all_maps_empty();

    // Test Case 3: Pointer is partially tracked.
    source_pointer.insert_relative_value(heap_id.clone(), Bitvector::zero(32.into()).into());
    mock_state.add_new_stack_offset_to_string_entry(4, CharacterInclusionDomain::Top);
    assert!(mock_state.pointer_added_to_variable_maps(
        &pi_state,
        &output_var,
        source_pointer.clone()
    ));
    assert_eq!(
        source_pointer,
        *mock_state
            .get_variable_to_pointer_map()
            .get(&output_var)
            .unwrap()
    );
    assert_eq!(
        CharacterInclusionDomain::Top,
        *mock_state.get_heap_to_string_map().get(&heap_id).unwrap()
    );
    mock_state.set_all_maps_empty();

    // Test Case 4: Pointer is not tracked.
    assert!(!mock_state.pointer_added_to_variable_maps(&pi_state, &output_var, source_pointer));
}

#[test]
fn test_pointer_targets_partially_tracked() {
    let mut mock_state =
        State::<CharacterInclusionDomain>::mock_with_default_pi_state(Sub::mock("func"));
    let pi_state = mock_state.get_pointer_inference_state().unwrap().clone();

    let heap_id = AbstractIdentifier::new(
        Tid::new("heap"),
        AbstractLocation::from_var(&variable!("r0:4")).unwrap(),
    );
    let stack_id = pi_state.stack_id.clone();

    let mut string_pointer = DataDomain::from_target(
        heap_id.clone(),
        IntervalDomain::new(Bitvector::from_i32(0), Bitvector::from_i32(0)),
    );

    string_pointer.insert_relative_value(
        stack_id.clone(),
        IntervalDomain::new(Bitvector::from_i32(-8), Bitvector::from_i32(-8)),
    );

    mock_state.set_pointer_inference_state(Some(pi_state.clone()));

    assert!(!mock_state.pointer_targets_partially_tracked(&pi_state, &string_pointer));

    mock_state
        .stack_offset_to_string_map
        .insert(-8, CharacterInclusionDomain::Top);

    assert!(mock_state.pointer_targets_partially_tracked(&pi_state, &string_pointer));
    assert!(mock_state.heap_to_string_map.contains_key(&heap_id));
}

#[test]
fn test_pointer_is_in_pointer_maps() {
    let r2_reg = variable!("r2:4");
    let sp_reg = variable!("sp:4");
    let mut mock_state =
        State::<CharacterInclusionDomain>::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&sp_reg).unwrap(),
    );

    let string_pointer = DataDomain::from_target(
        stack_id,
        IntervalDomain::new(Bitvector::from_i32(0), Bitvector::from_i32(0)),
    );

    assert!(!mock_state.pointer_is_in_pointer_maps(&string_pointer));

    mock_state
        .stack_offset_to_pointer_map
        .insert(-4, string_pointer.clone());

    assert!(mock_state.pointer_is_in_pointer_maps(&string_pointer));

    mock_state.stack_offset_to_pointer_map.remove(&(-4i64));
    mock_state
        .variable_to_pointer_map
        .insert(r2_reg, string_pointer.clone());

    assert!(mock_state.pointer_is_in_pointer_maps(&string_pointer));
}

#[test]
fn test_handle_store() {
    let block_first_def_set: HashSet<(Tid, Tid)> = HashSet::new();
    let target_var = variable!("r2:4");
    let value_var = variable!("r3:4");
    let value_location = Expression::Var(value_var.clone());
    let sp_reg = variable!("sp:4");
    let target_location = Expression::Var(target_var.clone());
    let runtime_memory_image = RuntimeMemoryImage::mock();
    let mut mock_state =
        State::<CharacterInclusionDomain>::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&sp_reg).unwrap(),
    );

    let string_pointer = DataDomain::from_target(
        stack_id.clone(),
        IntervalDomain::new(Bitvector::from_i32(8), Bitvector::from_i32(8)),
    );

    let target_address: DataDomain<IntervalDomain> = DataDomain::from_target(
        stack_id,
        IntervalDomain::new(Bitvector::from_i32(0), Bitvector::from_i32(0)),
    );

    let mut pi_state = mock_state.get_pointer_inference_state().unwrap().clone();
    pi_state.set_register(&target_var, target_address.clone());
    pi_state.set_register(&value_var, string_pointer.clone());
    pi_state
        .store_value(&target_address, &string_pointer, &runtime_memory_image)
        .unwrap();
    mock_state.set_pointer_inference_state(Some(pi_state));

    // Test Case 1: Pointer is no tracked string pointer.
    mock_state.handle_store(
        &target_location,
        &value_location,
        &runtime_memory_image,
        &block_first_def_set,
    );

    assert!(mock_state.stack_offset_to_pointer_map.is_empty());

    // Test Case 2: Pointer is an unassigned string pointer returned from a symbol call.
    mock_state
        .unassigned_return_pointer
        .insert(string_pointer.clone());

    mock_state.handle_store(
        &target_location,
        &value_location,
        &runtime_memory_image,
        &block_first_def_set,
    );

    assert_eq!(
        string_pointer,
        *mock_state.stack_offset_to_pointer_map.get(&(0i64)).unwrap()
    );
    assert!(mock_state.unassigned_return_pointer.is_empty());

    // Test Case 3: Pointer is already tracked.
    mock_state.set_all_maps_empty();
    mock_state
        .variable_to_pointer_map
        .insert(variable!("r0:4"), string_pointer.clone());

    mock_state.handle_store(
        &target_location,
        &value_location,
        &runtime_memory_image,
        &block_first_def_set,
    );

    assert_eq!(
        string_pointer,
        *mock_state.stack_offset_to_pointer_map.get(&(0i64)).unwrap()
    );

    // Test Case 4: Pointer is partially tracked.
    mock_state.set_all_maps_empty();
    mock_state
        .variable_to_pointer_map
        .insert(variable!("r0:4"), string_pointer.clone());
    // Test Case 5: Global address pointer as constant.
    // Test Case 6: Global address pointer in variable.
}

#[test]
fn test_add_pointer_to_stack_map() {
    let r2_reg = variable!("r2:4");
    let sp_reg = variable!("sp:4");
    let target = Expression::Var(r2_reg.clone());
    let mut mock_state =
        State::<CharacterInclusionDomain>::mock_with_default_pi_state(Sub::mock("func"));

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&sp_reg).unwrap(),
    );

    let string_pointer: DataDomain<IntervalDomain> = DataDomain::from_target(
        stack_id,
        IntervalDomain::new(Bitvector::from_i32(0), Bitvector::from_i32(0)),
    );

    let mut pi_state = mock_state.get_pointer_inference_state().unwrap().clone();
    pi_state.set_register(&r2_reg, string_pointer.clone());
    mock_state.set_pointer_inference_state(Some(pi_state));

    mock_state.add_pointer_to_stack_map(&target, string_pointer);

    assert!(mock_state.stack_offset_to_pointer_map.contains_key(&0));
}

#[test]
fn test_remove_non_callee_saved_pointer_entries_for_external_symbol() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );

    let mut mock_state = State::<CharacterInclusionDomain>::mock_with_default_pi_state(
        project.program.term.subs.values().next().unwrap().clone(),
    );

    let top_domain = DataDomain::new_empty(ByteSize::new(4));

    mock_state
        .variable_to_pointer_map
        .insert(variable!("r0:4"), top_domain.clone());
    mock_state
        .variable_to_pointer_map
        .insert(variable!("r11:4"), top_domain);

    mock_state
        .remove_non_callee_saved_pointer_entries_for_external_symbol(&project, &sprintf_symbol);

    assert!(!mock_state
        .variable_to_pointer_map
        .contains_key(&variable!("r0:4")));
    assert!(mock_state
        .variable_to_pointer_map
        .contains_key(&variable!("r11:4")));
}
