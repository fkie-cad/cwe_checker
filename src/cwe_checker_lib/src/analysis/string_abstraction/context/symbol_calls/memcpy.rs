use anyhow::Error;

use crate::abstract_domain::AbstractIdentifier;
use crate::analysis::pointer_inference::State as PointerInferenceState;
use crate::{
    abstract_domain::{
        AbstractDomain, DataDomain, DomainInsertion, HasTop, IntervalDomain, TryToBitvec,
    },
    analysis::string_abstraction::{context::Context, state::State},
    intermediate_representation::*,
};
use std::collections::BTreeMap;

use crate::prelude::*;

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
    /// Handles the detection of string parameters to memcpy calls.
    pub fn handle_memcpy_calls(&self, state: &State<T>, extern_symbol: &ExternSymbol) -> State<T> {
        let mut new_state = state.clone();
        if let Some(pi_state) = state.get_pointer_inference_state() {
            if let Ok(return_target) = self.has_return_target(extern_symbol, pi_state) {
                let mut input_target = None;
                if let Ok(input_data) = self.has_input_target(extern_symbol, pi_state) {
                    input_target = Some(input_data)
                }

                self.process_domains_for_memcpy_calls(
                    &mut new_state,
                    pi_state,
                    return_target,
                    input_target,
                );
            }
        }

        new_state
    }

    /// Checks whether the first input parameter contains a return target.
    pub fn has_return_target(
        &self,
        extern_symbol: &ExternSymbol,
        pi_state: &PointerInferenceState,
    ) -> Result<DataDomain<IntervalDomain>, Error> {
        if let Some(return_arg) = extern_symbol.parameters.first() {
            if let Ok(return_data) =
                pi_state.eval_parameter_arg(return_arg, &self.project.runtime_memory_image)
            {
                if !return_data.get_relative_values().is_empty() {
                    return Ok(return_data);
                }
            }
        }

        Err(anyhow!("No return value"))
    }

    /// Checks whether the second input parameter contains a source target.
    pub fn has_input_target(
        &self,
        extern_symbol: &ExternSymbol,
        pi_state: &PointerInferenceState,
    ) -> Result<DataDomain<IntervalDomain>, Error> {
        if let Some(input_arg) = extern_symbol.parameters.get(1) {
            return pi_state.eval_parameter_arg(input_arg, &self.project.runtime_memory_image);
        }

        Err(anyhow!("No input values"))
    }

    /// Processes string domains in memcpy calls on a case by case basis.
    ///
    /// - **Case 1**: Both the destination pointer domain and the source pointer domain have multiple
    /// targets. In this case all targets of the destination pointer receive *Top* values as
    /// it is unclear which source target correspondence to which destination target due to
    /// path insentivity.
    ///
    /// - **Case 2**: Only the destination pointer domain has multiple targets. In this case
    /// it is checked whether a string domain is tracked at the corresponding source position. If so,
    /// a new map entry is created for the string domain at all destination targets.
    /// Otherwise, a *Top* value is created.
    ///
    /// - **Case 3**: Both pointer domains have unique targets. In this case a potential string domain
    /// is simply copied to the destination target.
    ///
    /// Note that it is assumed that a memcpy input is always a string as it is part of the *string.h*
    /// C header file.
    pub fn process_domains_for_memcpy_calls(
        &self,
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        return_data: DataDomain<IntervalDomain>,
        input_data: Option<DataDomain<IntervalDomain>>,
    ) {
        let relative_return_targets = return_data.get_relative_values();
        if let Some(input_target) = input_data {
            if relative_return_targets.len() > 1
                && Context::<T>::has_multiple_targets(&input_target)
            {
                Context::<T>::add_new_string_abstract_domain(
                    state,
                    pi_state,
                    relative_return_targets,
                    T::create_top_value_domain(),
                );
            } else {
                self.process_domains_for_memcpy_calls_with_one_unique_input(
                    state,
                    pi_state,
                    &input_target,
                    relative_return_targets,
                )
            }
        } else {
            Context::<T>::add_new_string_abstract_domain(
                state,
                pi_state,
                relative_return_targets,
                T::create_top_value_domain(),
            );
        }
    }

    /// Processes domains for memcpy calls where at least one of
    /// the parameters contains a unique target.
    pub fn process_domains_for_memcpy_calls_with_one_unique_input(
        &self,
        state: &mut State<T>,
        pi_state: &PointerInferenceState,
        input_target: &DataDomain<IntervalDomain>,
        relative_return_targets: &BTreeMap<AbstractIdentifier, IntervalDomain>,
    ) {
        let domain_from_global_constant: Option<T> = self.get_constant_target(input_target);

        let mut domain_from_relative_targets: Option<T> = None;
        if !input_target.get_relative_values().is_empty() {
            domain_from_relative_targets =
                Some(Context::<T>::merge_domains_from_multiple_pointer_targets(
                    state,
                    pi_state,
                    input_target.get_relative_values(),
                ));
        }

        let output_domain: Option<T> =
            match (domain_from_global_constant, domain_from_relative_targets) {
                (Some(constant), Some(relative)) => Some(constant.merge(&relative)),
                (Some(constant), None) => Some(constant),
                (None, Some(relative)) => Some(relative),
                _ => None,
            };

        if let Some(output) = output_domain {
            Context::<T>::add_new_string_abstract_domain(
                state,
                pi_state,
                relative_return_targets,
                output,
            );
        }
    }

    /// Returns the content of a global memory target if there is some.
    pub fn get_constant_target(&self, input_target: &DataDomain<IntervalDomain>) -> Option<T> {
        if let Some(global_address) = input_target.get_absolute_value() {
            if let Ok(address_value) = global_address.try_to_bitvec() {
                if let Some(constant_domain) = self.get_constant_string_domain(address_value) {
                    return Some(constant_domain);
                }
            }
        }

        None
    }

    /// Checks whether a data domain has multiple targets.
    pub fn has_multiple_targets(data: &DataDomain<IntervalDomain>) -> bool {
        let number_of_relative_targets = data.get_relative_values().len();
        if let Some(global_address) = data.get_absolute_value() {
            if global_address.try_to_bitvec().is_ok() {
                // One global target + at least one relative target.
                if number_of_relative_targets >= 1 {
                    return true;
                }
            } else {
                // Multiple global targets.
                return true;
            }
        // More than one relative target and no global targets.
        } else if number_of_relative_targets > 1 {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        abstract_domain::{
            AbstractIdentifier, AbstractLocation, CharacterInclusionDomain, CharacterSet,
        },
        analysis::pointer_inference::PointerInference as PointerInferenceComputation,
        analysis::string_abstraction::{
            context::symbol_calls::tests::Setup,
            tests::mock_project_with_intraprocedural_control_flow,
        },
        intermediate_representation::{Bitvector, Tid},
        variable,
    };
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn test_handle_memcpy_calls_with_multiple_source_targets() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let heap_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
        );

        let mut parameter_pointer: DataDomain<IntervalDomain> =
            DataDomain::from_target(stack_id.clone(), Bitvector::from_i32(4).into());

        parameter_pointer.insert_relative_value(heap_id.clone(), Bitvector::from_i32(0).into());
        setup
            .state_before_call
            .add_new_stack_offset_to_string_entry(
                4,
                CharacterInclusionDomain::from("a".to_string()),
            );
        setup
            .state_before_call
            .add_new_heap_to_string_entry(heap_id, CharacterInclusionDomain::from("b".to_string()));

        setup
            .pi_state_before_symbol_call
            .set_register(&variable!("r1:4"), parameter_pointer);

        setup
            .state_before_call
            .set_pointer_inference_state(Some(setup.pi_state_before_symbol_call));

        // Test Case: destination pointer has multiple targets and source pointer has a unique target.
        let new_state = setup
            .context
            .handle_memcpy_calls(&setup.state_before_call, &memcpy_symbol);

        let expected_domain = CharacterInclusionDomain::Value((
            CharacterSet::Value(BTreeSet::new()),
            CharacterSet::Value(vec!['a', 'b'].into_iter().collect()),
        ));

        assert_eq!(
            expected_domain,
            *new_state
                .get_stack_offset_to_string_map()
                .get(&-60)
                .unwrap()
        );
    }

    #[test]
    fn test_handle_memcpy_calls_with_unique_pointers() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        // Test Case: destination and source pointer have unique targets and source is global constant
        let new_state = setup
            .context
            .handle_memcpy_calls(&setup.state_before_call, &memcpy_symbol);
        assert_eq!(
            CharacterInclusionDomain::from("str1 str2 str3 str4".to_string()),
            *new_state
                .get_stack_offset_to_string_map()
                .get(&-60)
                .unwrap()
        );
    }

    #[test]
    fn test_has_return_target() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );

        let expected_data: DataDomain<IntervalDomain> =
            DataDomain::from_target(stack_id, IntervalDomain::mock_i32(-60, -60));
        assert_eq!(
            expected_data,
            setup
                .context
                .has_return_target(&memcpy_symbol, &setup.pi_state_before_symbol_call)
                .unwrap()
        );
    }

    #[test]
    fn test_has_input_target() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let expected_data: DataDomain<IntervalDomain> =
            DataDomain::from(Bitvector::from_i32(0x7000));
        assert_eq!(
            expected_data,
            setup
                .context
                .has_input_target(&memcpy_symbol, &setup.pi_state_before_symbol_call)
                .unwrap()
        );
    }

    #[test]
    fn test_process_domains_for_memcpy_calls() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let return_targets = setup
            .pi_state_before_symbol_call
            .get_register(&variable!("r0:4"));

        let input_target: DataDomain<IntervalDomain> = DataDomain::from(
            setup
                .pi_state_before_symbol_call
                .get_register(&variable!("r1:4"))
                .get_absolute_value()
                .unwrap()
                .clone(),
        );

        setup.context.process_domains_for_memcpy_calls(
            &mut setup.state_before_call,
            &setup.pi_state_before_symbol_call,
            return_targets,
            Some(input_target),
        );

        assert_eq!(
            CharacterInclusionDomain::ci("str1 str2 str3 str4"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-60)
                .unwrap()
        );
    }

    #[test]
    fn test_process_domains_for_memcpy_calls_with_one_unique_input() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let mut setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);

        let return_targets = setup
            .pi_state_before_symbol_call
            .get_register(&variable!("r0:4"))
            .get_relative_values()
            .clone();

        let input_target: DataDomain<IntervalDomain> = DataDomain::from(
            setup
                .pi_state_before_symbol_call
                .get_register(&variable!("r1:4"))
                .get_absolute_value()
                .unwrap()
                .clone(),
        );

        setup
            .context
            .process_domains_for_memcpy_calls_with_one_unique_input(
                &mut setup.state_before_call,
                &setup.pi_state_before_symbol_call,
                &input_target,
                &return_targets,
            );

        assert_eq!(
            CharacterInclusionDomain::ci("str1 str2 str3 str4"),
            *setup
                .state_before_call
                .get_stack_offset_to_string_map()
                .get(&-60)
                .unwrap()
        );
    }

    #[test]
    fn test_get_constant_target() {
        let memcpy_symbol = ExternSymbol::mock_memcpy_symbol_arm();
        let project = mock_project_with_intraprocedural_control_flow(
            vec![(memcpy_symbol.clone(), vec![true])],
            "func",
        );
        let mut pi_results = PointerInferenceComputation::mock(&project);
        pi_results.compute(false);

        let setup: Setup<CharacterInclusionDomain> = Setup::new(&pi_results);
        let input_target = DataDomain::from(Bitvector::from_i32(0x7000));

        assert_eq!(
            CharacterInclusionDomain::ci("str1 str2 str3 str4"),
            setup.context.get_constant_target(&input_target).unwrap()
        );
    }

    #[test]
    fn test_has_multiple_targets() {
        let stack_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("sp:4")).unwrap(),
        );
        let heap_id = AbstractIdentifier::new(
            Tid::new("func"),
            AbstractLocation::from_var(&variable!("r5:4")).unwrap(),
        );
        // Test Case 1: Only one relative target.
        let mut data: DataDomain<IntervalDomain> = DataDomain::mock_from_target_map(
            vec![(stack_id.clone(), IntervalDomain::mock_i32(8, 8))]
                .into_iter()
                .collect(),
        );
        assert!(!Context::<CharacterInclusionDomain>::has_multiple_targets(
            &data
        ));

        // Test Case 2: On absolute value and at least one relative target.
        data.set_absolute_value(Some(IntervalDomain::mock_i32(0x7000, 0x7000)));
        assert!(Context::<CharacterInclusionDomain>::has_multiple_targets(
            &data
        ));

        // Test Case 3: Only an absolute value.
        data.set_relative_values(BTreeMap::new());
        assert!(!Context::<CharacterInclusionDomain>::has_multiple_targets(
            &data
        ));

        // Test Case 4: Multiple relative targets.
        data.set_absolute_value(None);
        data.insert_relative_value(stack_id, IntervalDomain::mock_i32(8, 8));
        data.insert_relative_value(heap_id, IntervalDomain::mock_i32(0, 0));
        assert!(Context::<CharacterInclusionDomain>::has_multiple_targets(
            &data
        ));

        // Test Case 5: Multiple absolute values.
        data.set_absolute_value(Some(IntervalDomain::mock_i32(0x7000, 0x7008)));
        data.set_relative_values(BTreeMap::new());
        assert!(Context::<CharacterInclusionDomain>::has_multiple_targets(
            &data
        ));
    }
}
