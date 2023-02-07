use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::{
    abstract_domain::{AbstractDomain, DomainInsertion, HasTop, TryToBitvec},
    analysis::string_abstraction::{context::Context, state::State},
    intermediate_representation::ExternSymbol,
};

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
    /// Handles the resulting string domain from strcat and strncat calls.
    /// The symbol call returns the pointer to the destination string in its return register.
    pub fn handle_strcat_and_strncat_calls(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
    ) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Some(return_arg) = extern_symbol.parameters.first() {
                if let Ok(return_pointer) =
                    pi_state.eval_parameter_arg(return_arg, &self.project.runtime_memory_image)
                {
                    if !return_pointer.get_relative_values().is_empty() {
                        let target_domain =
                            Context::<T>::merge_domains_from_multiple_pointer_targets(
                                state,
                                pi_state,
                                return_pointer.get_relative_values(),
                            );

                        Context::add_new_string_abstract_domain(
                            &mut new_state,
                            pi_state,
                            return_pointer.get_relative_values(),
                            target_domain.append_string_domain(&self.process_second_input_domain(
                                state,
                                extern_symbol,
                                pi_state,
                            )),
                        );

                        if let Ok(return_register) = extern_symbol.get_unique_return_register() {
                            new_state.add_new_variable_to_pointer_entry(
                                return_register.clone(),
                                return_pointer,
                            );
                        } else {
                            new_state.add_unassigned_return_pointer(return_pointer);
                        }
                    }
                }
            }
        }

        new_state
    }

    /// Processes the contents of the second input parameter.
    pub fn process_second_input_domain(
        &self,
        state: &State<T>,
        extern_symbol: &ExternSymbol,
        pi_state: &PointerInferenceState,
    ) -> T {
        let mut input_domain = T::create_top_value_domain();
        if let Some(input_arg) = extern_symbol.parameters.get(1) {
            if let Ok(input_value) =
                pi_state.eval_parameter_arg(input_arg, &self.project.runtime_memory_image)
            {
                // Check whether the second input string is in read only memory or on stack/heap.
                if !input_value.get_relative_values().is_empty() {
                    input_domain = Context::<T>::merge_domains_from_multiple_pointer_targets(
                        state,
                        pi_state,
                        input_value.get_relative_values(),
                    );
                }

                if let Some(value) = input_value.get_absolute_value() {
                    if let Ok(global_address) = value.try_to_bitvec() {
                        if let Ok(input_string) = self
                            .project
                            .runtime_memory_image
                            .read_string_until_null_terminator(&global_address)
                        {
                            if !input_domain.is_top() {
                                input_domain =
                                    input_domain.merge(&T::from(input_string.to_string()));
                            } else {
                                input_domain = T::from(input_string.to_string());
                            }
                        }
                    }
                }
            }
        }

        input_domain
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        abstract_domain::{CharacterInclusionDomain, CharacterSet, IntervalDomain},
        analysis::pointer_inference::PointerInference as PointerInferenceComputation,
        analysis::string_abstraction::{
            context::symbol_calls::tests::Setup,
            tests::mock_project_with_intraprocedural_control_flow,
        },
        intermediate_representation::*,
        variable,
    };

    #[test]
    fn test_handle_strcat_and_strncat_calls_with_known_second_input() {
        let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(strcat_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let expected_domain = CharacterInclusionDomain::Value((
            CharacterSet::Value(
                vec!['s', 't', 'r', ' ', '1', '2', '3', '4']
                    .into_iter()
                    .collect(),
            ),
            CharacterSet::Top,
        ));

        let new_state = setup
            .context
            .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

        assert_eq!(
            expected_domain,
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x3c as i64))
                .unwrap()
        );
    }

    #[test]
    fn test_handle_strcat_and_strncat_calls_with_unknown_second_input() {
        let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(strcat_symbol.clone(), vec![false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        // Test Case 1: No string domain is tracked for the second input.
        let new_state = setup
            .context
            .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

        assert_eq!(
            CharacterInclusionDomain::Top,
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x3c as i64))
                .unwrap()
        );

        // Test Case 2: A string domain is tracked for the second input.
        let expected_domain = CharacterInclusionDomain::Value((
            CharacterSet::Value(vec!['a'].into_iter().collect()),
            CharacterSet::Top,
        ));

        setup
            .state_before_call
            .add_new_stack_offset_to_string_entry(
                0x28,
                CharacterInclusionDomain::from("a".to_string()),
            );

        let new_state = setup
            .context
            .handle_strcat_and_strncat_calls(&setup.state_before_call, &strcat_symbol);

        assert_eq!(
            expected_domain,
            *new_state
                .get_stack_offset_to_string_map()
                .get(&(-0x3c as i64))
                .unwrap()
        );
    }

    #[test]
    fn test_process_second_input_domain_global() {
        let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(strcat_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        assert_eq!(
            CharacterInclusionDomain::ci("str1 str2 str3 str4"),
            setup.context.process_second_input_domain(
                &setup.state_before_call,
                &strcat_symbol,
                &setup.pi_state_before_symbol_call
            )
        );
    }

    #[test]
    fn test_process_second_input_domain_local() {
        let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(strcat_symbol.clone(), vec![false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        setup
            .state_before_call
            .add_new_stack_offset_to_string_entry(40, CharacterInclusionDomain::ci("abc"));

        assert_eq!(
            CharacterInclusionDomain::ci("abc"),
            setup.context.process_second_input_domain(
                &setup.state_before_call,
                &strcat_symbol,
                &setup.pi_state_before_symbol_call
            )
        );
    }

    #[test]
    fn test_process_second_input_domain_local_and_global() {
        let r1_reg = variable!("r1:4");
        let strcat_symbol = ExternSymbol::mock_strcat_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(strcat_symbol.clone(), vec![false])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let mut target_domain = setup.pi_state_before_symbol_call.get_register(&r1_reg);

        target_domain.set_absolute_value(Some(IntervalDomain::mock(0x7000, 0x7000)));

        setup
            .pi_state_before_symbol_call
            .set_register(&r1_reg, target_domain);

        setup
            .state_before_call
            .add_new_stack_offset_to_string_entry(40, CharacterInclusionDomain::ci("str"));

        let expected_domain = CharacterInclusionDomain::Value((
            CharacterSet::Value(vec!['s', 't', 'r'].into_iter().collect()),
            CharacterSet::Value(
                vec!['s', 't', 'r', '1', '2', '3', '4', ' ']
                    .into_iter()
                    .collect(),
            ),
        ));

        assert_eq!(
            expected_domain,
            setup.context.process_second_input_domain(
                &setup.state_before_call,
                &strcat_symbol,
                &setup.pi_state_before_symbol_call
            )
        );
    }
}
