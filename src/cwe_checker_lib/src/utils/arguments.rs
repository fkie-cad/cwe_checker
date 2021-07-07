//! Handles argument detection by parsing format string arguments during a function call. (e.g. sprintf)

use std::collections::HashMap;

use crate::{intermediate_representation::Datatype, prelude::*};

use regex::Regex;

use crate::{
    abstract_domain::{DataDomain, IntervalDomain, TryToBitvec},
    analysis::pointer_inference::State as PointerInferenceState,
    intermediate_representation::{
        Arg, ByteSize, CallingConvention, DatatypeProperties, ExternSymbol, Project, Variable,
    },
};

use super::binary::RuntimeMemoryImage;

/// Returns all return registers of a symbol as a vector of strings.
pub fn get_return_registers_from_symbol(symbol: &ExternSymbol) -> Vec<String> {
    symbol
        .return_values
        .iter()
        .filter_map(|ret| match ret {
            Arg::Register { var, .. } => Some(var.name.clone()),
            _ => None,
        })
        .collect::<Vec<String>>()
}

/// Parses the input format string for the corresponding string function.
pub fn get_input_format_string(
    pi_state: &PointerInferenceState,
    extern_symbol: &ExternSymbol,
    format_string_index: usize,
    stack_pointer_register: &Variable,
    runtime_memory_image: &RuntimeMemoryImage,
) -> Result<String, Error> {
    if let Some(format_string) = extern_symbol.parameters.get(format_string_index) {
        if let Ok(DataDomain::Value(address)) = pi_state.eval_parameter_arg(
            format_string,
            &stack_pointer_register,
            runtime_memory_image,
        ) {
            return parse_format_string_destination_and_return_content(
                address,
                runtime_memory_image,
            );
        }

        return Err(anyhow!("Format string not in global memory."));
    }

    Err(anyhow!(
        "No format string parameter at specified index {} for function {}",
        format_string_index,
        extern_symbol.name
    ))
}

/// Parses the destiniation address of the format string.
/// It checks whether the address points to another pointer in memory.
/// If so, it will use the target address of that pointer read the format string from memory.
pub fn parse_format_string_destination_and_return_content(
    address: IntervalDomain,
    runtime_memory_image: &RuntimeMemoryImage,
) -> Result<String, Error> {
    if let Ok(address_vector) = address.try_to_bitvec() {
        return match runtime_memory_image.read_string_until_null_terminator(&address_vector) {
            Ok(format_string) => Ok(format_string.to_string()),
            Err(e) => Err(anyhow!("{}", e)),
        };
    }

    Err(anyhow!(
        "Could not translate format string address to bitvector."
    ))
}

/// Parses the format string parameters using a regex, determines their data types,
/// and calculates their positions (register or memory).
pub fn parse_format_string_parameters(
    format_string: &str,
    datatype_properties: &DatatypeProperties,
) -> Result<Vec<(Datatype, ByteSize)>, Error> {
    let re = Regex::new(r#"%\d{0,2}(([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S])|(hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA))"#)
        .expect("No valid regex!");

    let datatype_map: Vec<(Datatype, ByteSize)> = re
        .captures_iter(format_string)
        .map(|cap| {
            let data_type = Datatype::from(cap[1].to_string());
            let size = {
                // Considers argument promotion for char type
                if matches!(data_type, Datatype::Char) {
                    datatype_properties.get_size_from_data_type(Datatype::Integer)
                } else {
                    datatype_properties.get_size_from_data_type(data_type.clone())
                }
            };
            (data_type, size)
        })
        .collect();

    let data_type_not_yet_parsable = datatype_map.iter().any(|(data_type, _)| {
        matches!(
            data_type,
            Datatype::Long | Datatype::LongLong | Datatype::LongDouble
        )
    });

    if data_type_not_yet_parsable {
        return Err(anyhow!(
            "Data types: long, long long and long double, cannot be parsed yet."
        ));
    }

    Ok(datatype_map)
}

/// Returns an argument vector of detected variable parameters if they are of type string.
pub fn get_variable_parameters(
    project: &Project,
    pi_state: &PointerInferenceState,
    extern_symbol: &ExternSymbol,
    format_string_index_map: &HashMap<String, usize>,
    runtime_memory_image: &RuntimeMemoryImage,
) -> Result<Vec<Arg>, Error> {
    let format_string_index = match format_string_index_map.get(&extern_symbol.name) {
        Some(index) => *index,
        None => panic!("External Symbol does not contain a format string parameter."),
    };

    let format_string_results = get_input_format_string(
        pi_state,
        extern_symbol,
        format_string_index,
        &project.stack_pointer_register,
        runtime_memory_image,
    );

    if let Ok(format_string) = format_string_results.as_ref() {
        if let Ok(parameters) =
            parse_format_string_parameters(format_string, &project.datatype_properties)
        {
            return Ok(calculate_parameter_locations(
                parameters,
                extern_symbol.get_calling_convention(project),
                format_string_index,
            ));
        }
    }

    Err(anyhow!(
        "Could not parse variable parameters: {}",
        format_string_results.unwrap_err()
    ))
}

/// Calculates the register and stack positions of format string parameters.
/// The parameters are then returned as an argument vector for later tainting.
pub fn calculate_parameter_locations(
    parameters: Vec<(Datatype, ByteSize)>,
    calling_convention: &CallingConvention,
    format_string_index: usize,
) -> Vec<Arg> {
    let mut var_args: Vec<Arg> = Vec::new();
    // The number of the remaining integer argument registers are calculated
    // from the format string position since it is the last fixed argument.
    let mut integer_arg_register_count =
        calling_convention.integer_parameter_register.len() - (format_string_index + 1);
    let mut float_arg_register_count = calling_convention.float_parameter_register.len();
    let mut stack_offset: i64 = 0;

    for (data_type, size) in parameters.iter() {
        match data_type {
            Datatype::Integer | Datatype::Pointer | Datatype::Char => {
                if integer_arg_register_count > 0 {
                    let register_name = calling_convention.integer_parameter_register
                        [calling_convention.integer_parameter_register.len()
                            - integer_arg_register_count]
                        .clone();

                    var_args.push(create_register_arg(*size, register_name, data_type.clone()));

                    integer_arg_register_count -= 1;
                } else {
                    var_args.push(create_stack_arg(*size, stack_offset, data_type.clone()));
                    stack_offset += u64::from(*size) as i64
                }
            }
            Datatype::Double => {
                if float_arg_register_count > 0 {
                    let register_name = calling_convention.float_parameter_register
                        [calling_convention.float_parameter_register.len()
                            - float_arg_register_count]
                        .clone();

                    var_args.push(create_register_arg(*size, register_name, data_type.clone()));

                    float_arg_register_count -= 1;
                } else {
                    var_args.push(create_stack_arg(*size, stack_offset, data_type.clone()));
                    stack_offset += u64::from(*size) as i64
                }
            }
            _ => panic!("Invalid data type specifier from format string."),
        }
    }

    var_args
}

/// Creates a stack parameter given a size, stack offset and data type.
pub fn create_stack_arg(size: ByteSize, stack_offset: i64, data_type: Datatype) -> Arg {
    Arg::Stack {
        offset: stack_offset,
        size,
        data_type: Some(data_type),
    }
}

/// Creates a register parameter given a size, register name and data type.
pub fn create_register_arg(size: ByteSize, register_name: String, data_type: Datatype) -> Arg {
    Arg::Register {
        var: Variable {
            name: register_name,
            size,
            is_temp: false,
        },
        data_type: Some(data_type),
    }
}

#[cfg(test)]
mod tests;
