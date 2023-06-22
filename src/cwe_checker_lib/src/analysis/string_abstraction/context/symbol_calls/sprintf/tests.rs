use std::collections::BTreeSet;

use super::*;
use crate::abstract_domain::{AbstractIdentifier, AbstractLocation};
use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
use crate::{
    abstract_domain::{CharacterInclusionDomain, CharacterSet},
    analysis::string_abstraction::{
        context::symbol_calls::tests::Setup, tests::mock_project_with_intraprocedural_control_flow,
    },
};
use crate::{bitvec, expr, intermediate_representation::*, variable};

#[test]
fn test_handle_sprintf_and_snprintf_calls() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let new_state = setup
        .context
        .handle_sprintf_and_snprintf_calls(&setup.state_before_call, &sprintf_symbol);

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );
    let return_pointer: DataDomain<IntervalDomain> =
        DataDomain::from_target(stack_id, IntervalDomain::from(bitvec!("-84:4")));

    assert_eq!(
        return_pointer,
        **new_state
            .get_unassigned_return_pointer()
            .into_iter()
            .collect::<Vec<&DataDomain<IntervalDomain>>>()
            .get(0)
            .unwrap()
    );

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['t', 'o', 'W', 'a', 'c', 'l', ' ', 'd', 'r', 'e', 'H']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    assert_eq!(
        expected_domain,
        *new_state
            .get_stack_offset_to_string_map()
            .get(&-84)
            .unwrap()
    );
}

#[test]
fn test_parse_format_string_and_add_new_string_domain() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let format_string_index: usize = 1;
    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );
    let return_pointer: DataDomain<IntervalDomain> =
        DataDomain::from_target(stack_id, IntervalDomain::from(bitvec!("-84:4")));

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    setup.context.parse_format_string_and_add_new_string_domain(
        &mut setup.state_before_call,
        &setup.pi_state_before_symbol_call,
        &sprintf_symbol,
        format_string_index,
        &return_pointer,
    );

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['t', 'o', 'W', 'a', 'c', 'l', ' ', 'd', 'r', 'e', 'H']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    assert_eq!(
        expected_domain,
        *setup
            .state_before_call
            .get_stack_offset_to_string_map()
            .get(&-84)
            .unwrap()
    );
}

#[test]
fn test_create_string_domain_for_sprintf_snprintf() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(
            vec!['t', 'o', 'W', 'a', 'c', 'l', ' ', 'd', 'r', 'e', 'H']
                .into_iter()
                .collect(),
        ),
        CharacterSet::Top,
    ));

    assert_eq!(
        expected_domain,
        setup.context.create_string_domain_for_sprintf_snprintf(
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call,
            &sprintf_symbol,
            "cat %s %s %s %s".to_string(),
        )
    );
}

#[test]
fn test_create_string_domain_using_data_type_approximations() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let format_string = "Hello %d %s %c %f.";

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(vec!['H', 'e', 'l', 'o', ' ', '.'].into_iter().collect()),
        CharacterSet::Top,
    ));

    assert_eq!(
        expected_domain,
        setup
            .context
            .create_string_domain_using_data_type_approximations(format_string.to_string())
    );
}

#[test]
fn test_create_string_domain_using_constants_and_sub_domains() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let string_arg = Arg::Register {
        expr: Expression::Var(variable!("r6:4")),
        data_type: Some(Datatype::Pointer),
    };
    let integer_arg = Arg::Register {
        expr: Expression::Var(variable!("r7:4")),
        data_type: Some(Datatype::Integer),
    };
    let char_arg = Arg::Register {
        expr: Expression::Var(variable!("r8:4")),
        data_type: Some(Datatype::Char),
    };

    let var_args: Vec<Arg> = vec![string_arg, integer_arg, char_arg];
    let format_string = "cat %s > %d %c";

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    setup.pi_state_before_symbol_call.set_register(
        &variable!("r6:4"),
        DataDomain::from(IntervalDomain::new(
            bitvec!("0x3002:8"),
            bitvec!("0x3002:8"),
        )),
    );

    setup.pi_state_before_symbol_call.set_register(
        &variable!("r7:4"),
        DataDomain::from(IntervalDomain::new(bitvec!("2:8"), bitvec!("2:8"))),
    );

    setup.pi_state_before_symbol_call.set_register(
        &variable!("r8:4"),
        DataDomain::from(IntervalDomain::new(bitvec!("0x42:8"), bitvec!("0x42:8"))),
    );

    let result_domain = setup
        .context
        .create_string_domain_using_constants_and_sub_domains(
            format_string.to_string(),
            &var_args,
            &setup.pi_state_before_symbol_call,
            &setup.state_before_call,
        );

    assert_eq!(
        CharacterInclusionDomain::from("cat >HeloWrd2B".to_string()),
        result_domain
    )
}

#[test]
fn test_push_format_specifier_approximation() {
    let mut domains: Vec<CharacterInclusionDomain> = vec![];
    let format_string = "Hello %d welcome to %s and %c, %f.";
    let re = Context::<CharacterInclusionDomain>::re_format_specifier();
    let matches: Vec<Match> = re.find_iter(&format_string).into_iter().collect();
    for mat in matches.into_iter() {
        Context::<CharacterInclusionDomain>::push_format_specifier_approximation(&mut domains, mat);
    }

    assert_eq!(
        vec![
            CharacterInclusionDomain::create_integer_domain(),
            CharacterInclusionDomain::Top,
            CharacterInclusionDomain::Top,
            CharacterInclusionDomain::create_float_value_domain(),
        ],
        domains
    );
}

#[test]
fn test_push_constant_subsequences_before_and_between_specifiers() {
    let mut domains: Vec<CharacterInclusionDomain> = vec![];
    let format_string = "Hello %s welcome to %s";
    let re = Context::<CharacterInclusionDomain>::re_format_specifier();
    let matches: Vec<Match> = re.find_iter(&format_string).into_iter().collect();
    let mut specifier_ends: Vec<usize> = vec![0];
    specifier_ends.push(matches.get(0).unwrap().end());

    for (index, (mat, spec_end)) in std::iter::zip(matches, specifier_ends)
        .into_iter()
        .enumerate()
    {
        Context::<CharacterInclusionDomain>::push_constant_subsequences_before_and_between_specifiers(&mut domains, format_string, mat, spec_end, index);
    }

    assert_eq!(
        vec![
            CharacterInclusionDomain::ci("Hello "),
            CharacterInclusionDomain::ci(" welcome to ")
        ],
        domains
    );
}

#[test]
fn test_push_constant_suffix_if_available() {
    let mut domains: Vec<CharacterInclusionDomain> = vec![];
    Context::<CharacterInclusionDomain>::push_constant_suffix_if_available(
        &mut domains,
        "Hello world",
        6,
    );
    assert_eq!(
        CharacterInclusionDomain::ci("world"),
        *domains.get(0).unwrap()
    );
    domains.clear();
    Context::<CharacterInclusionDomain>::push_constant_suffix_if_available(
        &mut domains,
        "Hello world",
        11,
    );
    assert_eq!(Vec::<CharacterInclusionDomain>::new(), domains);
    Context::<CharacterInclusionDomain>::push_constant_suffix_if_available(
        &mut domains,
        "Hello world",
        0,
    );
    assert_eq!(
        CharacterInclusionDomain::ci("Hello world"),
        *domains.get(0).unwrap()
    );
    domains.clear();
}

#[test]
fn test_concat_domains() {
    assert_eq!(
        CharacterInclusionDomain::ci("ab"),
        Context::<CharacterInclusionDomain>::concat_domains(&mut vec![
            CharacterInclusionDomain::ci("a"),
            CharacterInclusionDomain::ci("b")
        ])
    );
}

#[test]
fn test_no_specifiers() {
    // Test Case 1: No specifiers in format string.
    assert!(!Context::<CharacterInclusionDomain>::no_specifiers(
        "%s".to_string()
    ));
    // Test Case 2: Specifiers in format string.
    assert!(Context::<CharacterInclusionDomain>::no_specifiers(
        "hello".to_string()
    ));
}

#[test]
fn test_fetch_constant_and_domain_for_format_specifier() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let string_arg = Arg::Register {
        expr: expr!("r6:4"),
        data_type: Some(Datatype::Pointer),
    };
    let integer_arg = Arg::Register {
        expr: expr!("r7:4"),
        data_type: Some(Datatype::Integer),
    };
    let char_arg = Arg::Register {
        expr: expr!("r8:4"),
        data_type: Some(Datatype::Char),
    };

    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(BTreeSet::new()),
        CharacterSet::Value("-0123456789".chars().collect()),
    ));

    // Test Case 1: Integer and no tracked value.
    assert_eq!(
        expected_domain,
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &integer_arg,
                "%d".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    // Test Case 2: String and no tracked value.
    assert_eq!(
        CharacterInclusionDomain::Top,
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &string_arg,
                "%S".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    // Test Case 3: Char and no tracked value.
    assert_eq!(
        CharacterInclusionDomain::Top,
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &char_arg,
                "%c".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    // Test Case 4: Integer and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &variable!("r7:4"),
        DataDomain::from(IntervalDomain::new(bitvec!("2:8"), bitvec!("2:8"))),
    );

    assert_eq!(
        CharacterInclusionDomain::from("2".to_string()),
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &integer_arg,
                "%d".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    // Test Case 5: Char and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &variable!("r8:4"),
        DataDomain::from(IntervalDomain::new(bitvec!("0x42:4"), bitvec!("0x42:4"))),
    );

    assert_eq!(
        CharacterInclusionDomain::from("B".to_string()),
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &char_arg,
                "%c".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    // Test Case 6: String and tracked constant.
    setup.pi_state_before_symbol_call.set_register(
        &variable!("r6:4"),
        DataDomain::from(IntervalDomain::new(
            bitvec!("0x3002:4"),
            bitvec!("0x3002:4"),
        )),
    );

    assert_eq!(
        CharacterInclusionDomain::from("Hello World".to_string()),
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &string_arg,
                "%s".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );

    let mut pointer: DataDomain<IntervalDomain> = DataDomain::from_target(
        stack_id,
        IntervalDomain::new(bitvec!("16:4"), bitvec!("16:4")),
    );

    let heap_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("r9:4")).unwrap(),
    );

    pointer.insert_relative_value(
        heap_id.clone(),
        IntervalDomain::new(bitvec!("0:4"), bitvec!("0:4")),
    );

    setup
        .state_before_call
        .add_new_stack_offset_to_string_entry(16, CharacterInclusionDomain::from("a".to_string()));
    setup
        .state_before_call
        .add_new_heap_to_string_entry(heap_id, CharacterInclusionDomain::from("b".to_string()));

    // Test Case 5: String and tracked domain.
    setup
        .pi_state_before_symbol_call
        .set_register(&variable!("r6:4"), pointer);

    let expected_domain = CharacterInclusionDomain::Value((
        CharacterSet::Value(BTreeSet::new()),
        CharacterSet::Value("ab".chars().collect()),
    ));

    assert_eq!(
        expected_domain,
        setup
            .context
            .fetch_constant_and_domain_for_format_specifier(
                &string_arg,
                "%s".to_string(),
                &setup.pi_state_before_symbol_call,
                &setup.state_before_call
            )
    );
}

#[test]
fn test_trim_format_specifier() {
    assert_eq!(
        "s".to_string(),
        Context::<CharacterInclusionDomain>::trim_format_specifier("%s".to_string())
    );
    assert_eq!(
        "d".to_string(),
        Context::<CharacterInclusionDomain>::trim_format_specifier("%02d".to_string())
    );
}

#[test]
fn test_fetch_subdomains_if_available() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

    // Test Case 1: No relative targets.
    assert_eq!(
        None,
        Context::<CharacterInclusionDomain>::fetch_subdomains_if_available(
            &DataDomain::<IntervalDomain>::new_empty(4.into()),
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &Arg::mock_register("r0", 4),
            None,
        )
    );

    let stack_id = AbstractIdentifier::new(
        Tid::new("func"),
        AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
    );

    // Test Case 2: Target value is not of type string pointer.
    assert_eq!(
        None,
        Context::<CharacterInclusionDomain>::fetch_subdomains_if_available(
            &DataDomain::from_target(stack_id.clone(), IntervalDomain::mock(16, 16)),
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &Arg::mock_register("r0", 4),
            None,
        )
    );

    setup
        .state_before_call
        .add_new_stack_offset_to_string_entry(16, CharacterInclusionDomain::ci("Hello World"));

    // Test Case 3: Target is of type string pointer.
    assert_eq!(
        Some(CharacterInclusionDomain::ci("Hello World")),
        Context::<CharacterInclusionDomain>::fetch_subdomains_if_available(
            &DataDomain::from_target(stack_id, IntervalDomain::mock(16, 16)),
            &setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            &Arg::mock_pointer_register("r0", 4),
            None,
        )
    );
}

#[test]
fn test_fetch_constant_domain_if_available() {
    let sprintf_symbol = ExternSymbol::mock_sprintf_symbol_arm();
    let project = mock_project_with_intraprocedural_control_flow(
        vec![(sprintf_symbol.clone(), vec![true])],
        "func",
    );
    let mut pi_results = PointerInferenceComputation::mock(&project);
    pi_results.compute(false);

    let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);
    let string_data: DataDomain<IntervalDomain> = DataDomain::from(bitvec!("0x7000:4"));
    let string_arg: Arg = Arg::mock_pointer_register("r0", 4);

    let integer_data: DataDomain<IntervalDomain> = DataDomain::from(bitvec!("2:4"));
    let integer_arg: Arg = Arg::mock_register_with_data_type("r0", 4, Some(Datatype::Integer));

    let char_data: DataDomain<IntervalDomain> = DataDomain::from(bitvec!("0x61:4"));
    let char_arg: Arg = Arg::mock_register_with_data_type("r0", 4, Some(Datatype::Char));

    assert_eq!(
        Some(CharacterInclusionDomain::ci("str1 str2 str3 str4")),
        setup
            .context
            .fetch_constant_domain_if_available(&string_data, &string_arg)
    );
    assert_eq!(
        Some(CharacterInclusionDomain::ci("2")),
        setup
            .context
            .fetch_constant_domain_if_available(&integer_data, &integer_arg)
    );
    assert_eq!(
        Some(CharacterInclusionDomain::ci("a")),
        setup
            .context
            .fetch_constant_domain_if_available(&char_data, &char_arg)
    );
}
