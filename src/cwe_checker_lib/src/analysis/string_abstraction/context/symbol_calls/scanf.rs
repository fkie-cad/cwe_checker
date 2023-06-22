use std::collections::HashMap;

use anyhow::Error;
use itertools::izip;

use crate::abstract_domain::TryToBitvec;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::prelude::*;
use crate::{
    abstract_domain::{AbstractDomain, DataDomain, DomainInsertion, HasTop, IntervalDomain},
    analysis::string_abstraction::{context::Context, state::State},
    intermediate_representation::{Arg, Datatype, ExternSymbol},
    utils::arguments::get_variable_parameters,
};

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
    /// Handles the detection of string parameters to scanf calls.
    /// Adds new string abstract domains to the current state.
    pub fn handle_scanf_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            // Check whether the format string parameters can be parsed.
            if let Ok(return_values) = get_variable_parameters(
                self.project,
                pi_state,
                extern_symbol,
                &self.format_string_index_map,
            ) {
                self.create_abstract_domain_entries_for_function_return_values(
                    pi_state,
                    &mut new_state,
                    return_values.into_iter().map(|arg| (arg, None)).collect(),
                );
            }
        }

        new_state
    }

    /// Creates string abstract domains for return values of (s)scanf calls.
    pub fn create_abstract_domain_entries_for_function_return_values(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State<T>,
        arg_to_value_map: HashMap<Arg, Option<String>>,
    ) {
        for (argument, value) in arg_to_value_map.into_iter() {
            if argument.get_data_type().unwrap() == Datatype::Pointer {
                if let Ok(data) =
                    pi_state.eval_parameter_arg(&argument, &self.project.runtime_memory_image)
                {
                    if !data.get_relative_values().is_empty() {
                        Context::add_constant_or_top_value_to_return_locations(
                            state, pi_state, data, value,
                        );
                    }
                }
            }
        }
    }

    /// Adds constant or *Top* value to return location given a pointer and a potential value.
    pub fn add_constant_or_top_value_to_return_locations(
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        return_target: DataDomain<IntervalDomain>,
        value: Option<String>,
    ) {
        if let Some(string) = value {
            Context::add_new_string_abstract_domain(
                state,
                pi_state,
                return_target.get_relative_values(),
                T::from(string),
            );
        } else {
            Context::add_new_string_abstract_domain(
                state,
                pi_state,
                return_target.get_relative_values(),
                T::create_top_value_domain(),
            );
        }

        state.add_unassigned_return_pointer(return_target);
    }

    /// Handles calls to sscanf. If the source string is known, it is split by spaces
    /// and for each substring a string abstract domain is generated at its corresponding location.
    pub fn handle_sscanf_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(source_string_arg) = extern_symbol.parameters.first() {
                if let Ok(source_string) = pi_state
                    .eval_parameter_arg(source_string_arg, &self.project.runtime_memory_image)
                {
                    if self.source_string_mapped_to_return_locations(
                        pi_state,
                        &mut new_state,
                        &source_string,
                        extern_symbol,
                    ) {
                        return new_state;
                    }
                }
            }
            new_state = self.handle_scanf_calls(&new_state, extern_symbol);
        }

        new_state
    }

    /// Maps the source string to the return locations of the call and returns an boolean
    /// which indicates whether the operation was successful.
    pub fn source_string_mapped_to_return_locations(
        &self,
        pi_state: &PointerInferenceState,
        state: &mut State<T>,
        source_string: &DataDomain<IntervalDomain>,
        extern_symbol: &ExternSymbol,
    ) -> bool {
        if let Some(global_address) = source_string.get_absolute_value() {
            if let Ok(source_string) = self
                .project
                .runtime_memory_image
                .read_string_until_null_terminator(
                    &global_address
                        .try_to_bitvec()
                        .expect("Could not translate interval address to bitvector."),
                )
            {
                if let Ok(source_return_string_map) = self
                    .map_source_string_parameters_to_return_arguments(
                        pi_state,
                        extern_symbol,
                        source_string,
                    )
                {
                    self.create_abstract_domain_entries_for_function_return_values(
                        pi_state,
                        state,
                        source_return_string_map,
                    );

                    return true;
                }
            }
        }

        false
    }

    /// Maps source strings parameters to return arguments for sscanf calls.
    pub fn map_source_string_parameters_to_return_arguments(
        &self,
        pi_state: &PointerInferenceState,
        extern_symbol: &ExternSymbol,
        source_string: &str,
    ) -> Result<HashMap<Arg, Option<String>>, Error> {
        if let Ok(all_parameters) = get_variable_parameters(
            self.project,
            pi_state,
            extern_symbol,
            &self.format_string_index_map,
        ) {
            let return_values: Vec<String> =
                source_string.split(' ').map(|s| s.to_string()).collect();

            return Ok(Context::<T>::filter_out_all_non_string_args(
                all_parameters,
                return_values,
            ));
        }

        Err(anyhow!("Could not map source string to return parameters."))
    }

    /// Filters out all parameters that are not of type string.
    pub fn filter_out_all_non_string_args(
        all_parameters: Vec<Arg>,
        return_values: Vec<String>,
    ) -> HashMap<Arg, Option<String>> {
        izip!(all_parameters, return_values)
            .filter_map(|(param, value)| {
                if matches!(param.get_data_type(), Some(Datatype::Pointer)) {
                    Some((param, Some(value)))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;
    use crate::abstract_domain::{AbstractIdentifier, AbstractLocation, CharacterInclusionDomain};
    use crate::analysis::pointer_inference::PointerInference as PointerInferenceComputation;
    use crate::analysis::string_abstraction::tests::mock_project_with_intraprocedural_control_flow;
    use crate::{expr, intermediate_representation::*, variable};

    #[test]
    fn test_handle_scanf_calls() {
        let scanf_symbol = ExternSymbol::mock_scanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(scanf_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let new_state = setup
            .context
            .handle_scanf_calls(&setup.state_before_call, &scanf_symbol);

        let top_value = CharacterInclusionDomain::from("".to_string()).top();

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x74).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x5e).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x4c).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x38).into(),
            )));

        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x74 as i64))
                .unwrap(),
            top_value,
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x5e as i64))
                .unwrap(),
            top_value,
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x4c as i64))
                .unwrap(),
            top_value,
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x38 as i64))
                .unwrap(),
            top_value,
        );
    }

    #[test]
    fn test_create_abstract_domain_entries_for_function_return_values_with_known_values() {
        let r2_reg = variable!("r2:4");
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![true, true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();

        let register_arg = Arg::Register {
            expr: Expression::Var(r2_reg.clone()),
            data_type: Some(Datatype::Pointer),
        };
        let stack_arg = Arg::Stack {
            address: expr!("sp:4"),
            size: ByteSize::new(4),
            data_type: Some(Datatype::Pointer),
        };
        arg_to_value_map.insert(register_arg, Some("a".to_string()));
        arg_to_value_map.insert(stack_arg, Some("b".to_string()));

        setup
            .context
            .create_abstract_domain_entries_for_function_return_values(
                &setup.pi_state_before_symbol_call,
                &mut setup.state_before_call,
                arg_to_value_map,
            );

        assert_eq!(
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&(-0x7c as i64))
                .unwrap(),
            CharacterInclusionDomain::from("a".to_string())
        );

        assert_eq!(
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&(-0x92 as i64))
                .unwrap(),
            CharacterInclusionDomain::from("b".to_string())
        );

        assert!(setup
            .state_before_call
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x7c).into(),
            )));

        assert!(setup
            .state_before_call
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x92).into(),
            )));
    }

    #[test]
    fn test_create_abstract_domain_entries_for_function_return_values_with_unknown_values() {
        let r1_reg = variable!("r1:4");
        let scanf_symbol = ExternSymbol::mock_scanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(scanf_symbol.clone(), vec![false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let mut arg_to_value_map: HashMap<Arg, Option<String>> = HashMap::new();
        let register_arg = Arg::Register {
            expr: Expression::Var(r1_reg.clone()),
            data_type: Some(Datatype::Pointer),
        };
        let stack_arg = Arg::Stack {
            address: expr!("sp:4"),
            size: ByteSize::new(4),
            data_type: Some(Datatype::Pointer),
        };
        arg_to_value_map.insert(register_arg, None);
        arg_to_value_map.insert(stack_arg, None);

        setup
            .context
            .create_abstract_domain_entries_for_function_return_values(
                &setup.pi_state_before_symbol_call,
                &mut setup.state_before_call,
                arg_to_value_map,
            );

        assert_eq!(
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&(-0x74 as i64))
                .unwrap(),
            CharacterInclusionDomain::Top
        );

        assert_eq!(
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&(-0x38 as i64))
                .unwrap(),
            CharacterInclusionDomain::Top
        );

        assert!(setup
            .state_before_call
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x74).into(),
            )));

        assert!(setup
            .state_before_call
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x38).into(),
            )));
    }

    #[test]
    fn test_add_constant_or_top_value_to_return_locations() {
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![false, false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let return_target: DataDomain<IntervalDomain> =
            DataDomain::from_target(stack_id, IntervalDomain::mock(-124, -124));

        Context::<CharacterInclusionDomain>::add_constant_or_top_value_to_return_locations(
            &mut setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            return_target.clone(),
            Some("str1".to_string()),
        );

        assert_eq!(
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-124)
                .unwrap(),
            CharacterInclusionDomain::ci("str1")
        );
        assert!(setup
            .state_before_call
            .get_unassigned_return_pointer()
            .contains(&return_target));
    }

    #[test]
    fn test_handle_sscanf_calls_unknown_source_unknown_format() {
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![false, false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let new_state = setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

        assert!(new_state.get_stack_offset_to_string_map().is_empty());
        assert!(new_state.get_unassigned_return_pointer().is_empty());
    }

    #[test]
    fn test_handle_sscanf_calls_known_source_unknown_format() {
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![true, false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let new_state = setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

        assert!(new_state.get_unassigned_return_pointer().is_empty());
        assert!(new_state.get_stack_offset_to_string_map().is_empty());
    }

    #[test]
    fn test_handle_sscanf_calls_unknown_source_known_format() {
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![false, true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let new_state = setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x7c as i64))
                .unwrap(),
            CharacterInclusionDomain::Top
        );

        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x92 as i64))
                .unwrap(),
            CharacterInclusionDomain::Top
        );

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x7c).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x92).into(),
            )));
    }

    #[test]
    fn test_handle_sscanf_calls_known_source_known_format() {
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![true, true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let new_state = setup
            .context
            .handle_sscanf_calls(&setup.state_before_call, &sscanf_symbol);

        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x7c as i64))
                .unwrap(),
            CharacterInclusionDomain::from("str1".to_string())
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x68 as i64))
                .unwrap(),
            CharacterInclusionDomain::from("str2".to_string())
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x92 as i64))
                .unwrap(),
            CharacterInclusionDomain::from("str3".to_string())
        );
        assert_eq!(
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x84 as i64))
                .unwrap(),
            CharacterInclusionDomain::from("str4".to_string())
        );

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x7c).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x68).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x92).into(),
            )));

        assert!(new_state
            .get_unassigned_return_pointer()
            .contains(&DataDomain::from_target(
                stack_id.clone(),
                Bitvector::from_i32(-0x84).into(),
            )));
    }

    #[test]
    fn test_source_string_mapped_to_return_locations() {
        let source_string: DataDomain<IntervalDomain> =
            DataDomain::from(Bitvector::from_i32(0x7000));
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![true, true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        setup.context.source_string_mapped_to_return_locations(
            &setup.pi_state_before_symbol_call,
            &mut setup.state_before_call,
            &source_string,
            &sscanf_symbol,
        );

        assert_eq!(
            CharacterInclusionDomain::ci("str1"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-124)
                .unwrap()
        );

        assert_eq!(
            CharacterInclusionDomain::ci("str2"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-104)
                .unwrap()
        );

        assert_eq!(
            CharacterInclusionDomain::ci("str4"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-132)
                .unwrap()
        );

        assert_eq!(
            CharacterInclusionDomain::ci("str3"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-146)
                .unwrap()
        );
    }

    #[test]
    fn test_map_source_string_parameters_to_return_arguments() {
        let source_string = "str1 str2 str3 str4";
        let sscanf_symbol = ExternSymbol::mock_sscanf_symbol_arm();

        let project = mock_project_with_intraprocedural_control_flow(
            vec![(sscanf_symbol.clone(), vec![true, true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let expected_result: HashMap<Arg, Option<String>> = vec![
            (
                Arg::mock_pointer_register("r2", 4),
                Some("str1".to_string()),
            ),
            (
                Arg::mock_pointer_register("r3", 4),
                Some("str2".to_string()),
            ),
            (
                Arg::Stack {
                    address: expr!("sp:4"),
                    size: ByteSize::new(4),
                    data_type: Some(Datatype::Pointer),
                },
                Some("str3".to_string()),
            ),
            (
                Arg::Stack {
                    address: expr!("sp:4 + 4:4"),
                    size: ByteSize::new(4),
                    data_type: Some(Datatype::Pointer),
                },
                Some("str4".to_string()),
            ),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            expected_result,
            setup
                .context
                .map_source_string_parameters_to_return_arguments(
                    &setup.pi_state_before_symbol_call,
                    &sscanf_symbol,
                    source_string
                )
                .unwrap()
        );
    }

    #[test]
    fn test_filter_out_all_non_string_args() {
        let args = vec![
            Arg::mock_pointer_register("r0", 4),
            Arg::mock_register("r1", 4),
        ];
        let values = vec!["cat ".to_string(), "2".to_string()];

        let expected_output: HashMap<Arg, Option<String>> = vec![(
            Arg::mock_pointer_register("r0", 4),
            Some("cat ".to_string()),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            expected_output,
            Context::<CharacterInclusionDomain>::filter_out_all_non_string_args(args, values)
        );
    }
}
