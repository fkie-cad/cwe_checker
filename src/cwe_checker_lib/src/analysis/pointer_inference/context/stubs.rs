use super::*;

impl<'a> Context<'a> {
    /// Handle the parameters of a call to sscanf by assuming that arbitrary values are written to the targets of the variadic parameters.
    pub fn handle_params_of_sscanf_call(
        &self,
        state: &State,
        new_state: &mut State,
        sscanf_symbol: &ExternSymbol,
        call_tid: &Tid,
    ) -> Result<(), Error> {
        use crate::utils::arguments;

        let format_string_address = state
            .eval_parameter_arg(
                &sscanf_symbol.parameters[1],
                &self.project.runtime_memory_image,
            )?
            .get_if_absolute_value()
            .ok_or_else(|| anyhow!("Format string may not be a constant string"))?
            .try_to_bitvec()?;
        let format_string = arguments::parse_format_string_destination_and_return_content(
            format_string_address,
            &self.project.runtime_memory_image,
        )?;
        // Calculate the data types of the parameters
        let format_string_param_types = arguments::parse_format_string_parameters(
            &format_string,
            &self.project.datatype_properties,
        )?;
        // All variadic parameters are pointers (to their respective data types)
        let format_string_params =
            vec![
                (Datatype::Pointer, self.project.stack_pointer_register.size);
                format_string_param_types.len()
            ];
        let format_string_args = arguments::calculate_parameter_locations(
            format_string_params,
            sscanf_symbol,
            self.project,
        );
        for (arg, (datatype, size)) in format_string_args
            .iter()
            .zip(format_string_param_types.iter())
        {
            if let Ok(param) = state.eval_parameter_arg(arg, &self.project.runtime_memory_image) {
                if *datatype != Datatype::Pointer {
                    self.log_debug(
                        new_state.store_value(
                            &param,
                            &Data::new_top(*size),
                            &self.project.runtime_memory_image,
                        ),
                        Some(call_tid),
                    );
                } else {
                    for id in param.referenced_ids() {
                        new_state
                            .memory
                            .assume_arbitrary_writes_to_object(id, &BTreeSet::new());
                    }
                }
            }
        }
        Ok(())
    }

    /// For stubbed function that may write to a memory object provided through a parameter
    /// we assume for the corresponding memory objects that arbitrary writes to them may have happened.
    ///
    /// This function uses the same access patterns for stubbed functions as the [`function_signature`](crate::analysis::function_signature) analysis
    /// for determine which parameters are accessed mutably.
    pub fn handle_parameter_access_for_stubbed_functions(
        &self,
        state: &State,
        new_state: &mut State,
        extern_symbol: &ExternSymbol,
    ) {
        let access_patterns = self
            .extern_fn_param_access_patterns
            .get(extern_symbol.name.as_str())
            .unwrap();
        for (arg, access_pattern) in extern_symbol.parameters.iter().zip(access_patterns.iter()) {
            if access_pattern.is_mutably_dereferenced() {
                if let Ok(param) = state.eval_parameter_arg(arg, &self.project.runtime_memory_image)
                {
                    for id in param.referenced_ids() {
                        new_state
                            .memory
                            .assume_arbitrary_writes_to_object(id, &BTreeSet::new());
                    }
                }
            }
        }
    }

    /// Compute the return values for stubbed extern symbols.
    /// Note that this function does not handle malloc-like symbols that return a newly created heap object as a return value.
    pub fn compute_return_value_for_stubbed_function(
        &self,
        state: &State,
        extern_symbol: &ExternSymbol,
    ) -> Data {
        use return_value_stubs::*;
        match extern_symbol.name.as_str() {
            "memcpy" | "memmove" | "memset" | "strcat" | "strcpy" | "strncat" | "strncpy" => {
                copy_param(state, extern_symbol, 0, &self.project.runtime_memory_image)
            }
            "fgets" => or_null(copy_param(
                state,
                extern_symbol,
                0,
                &self.project.runtime_memory_image,
            )),
            "strchr" | "strrchr" | "strstr" => or_null(param_plus_unknown_offset(
                state,
                extern_symbol,
                0,
                &self.project.runtime_memory_image,
            )),
            _ => untracked(self.project.stack_pointer_register.size),
        }
    }
}

/// Helper functions for computing return values for extern symbol calls.
pub mod return_value_stubs {
    use super::*;

    /// An untracked value is just a `Top` value.
    /// It is used for any non-pointer return values.
    pub fn untracked(register_size: ByteSize) -> Data {
        Data::new_top(register_size)
    }

    /// A return value that is just a copy of a parameter.
    pub fn copy_param(
        state: &State,
        extern_symbol: &ExternSymbol,
        param_index: usize,
        global_memory: &RuntimeMemoryImage,
    ) -> Data {
        state
            .eval_parameter_arg(&extern_symbol.parameters[param_index], global_memory)
            .unwrap_or_else(|_| Data::new_top(extern_symbol.parameters[param_index].bytesize()))
    }

    /// A return value that adds an unknown offset to a given parameter.
    /// E.g. if the parameter is a pointer to a string,
    /// this return value would describe a pointer to an offset inside the string.
    pub fn param_plus_unknown_offset(
        state: &State,
        extern_symbol: &ExternSymbol,
        param_index: usize,
        global_memory: &RuntimeMemoryImage,
    ) -> Data {
        let param = state
            .eval_parameter_arg(&extern_symbol.parameters[param_index], global_memory)
            .unwrap_or_else(|_| Data::new_top(extern_symbol.parameters[param_index].bytesize()));
        param.add_offset(&IntervalDomain::new_top(param.bytesize()))
    }

    /// The return value may also be zero in addition to its other possible values.
    pub fn or_null(data: Data) -> Data {
        data.merge(&Bitvector::zero(data.bytesize().into()).into())
    }
}
