//! Handles argument detection by parsing format string arguments during a function call. (e.g. sprintf)

use std::collections::HashMap;

use crate::prelude::*;

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
            Arg::Register(var) => Some(var.name.clone()),
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
) -> Vec<(String, ByteSize)> {
    let re = Regex::new(r#"%\d{0,2}([c,C,d,i,o,u,x,X,e,E,f,F,g,G,a,A,n,p,s,S])"#)
        .expect("No valid regex!");

    re.captures_iter(format_string)
        .map(|cap| {
            (
                cap[1].to_string(),
                map_format_specifier_to_bytesize(datatype_properties, cap[1].to_string()),
            )
        })
        .collect()
}

/// Maps a given format specifier to the bytesize of its corresponding data type.
pub fn map_format_specifier_to_bytesize(
    datatype_properties: &DatatypeProperties,
    specifier: String,
) -> ByteSize {
    if is_integer(&specifier) {
        return datatype_properties.integer_size;
    }

    if is_float(&specifier) {
        return datatype_properties.double_size;
    }

    if is_pointer(&specifier) {
        return datatype_properties.pointer_size;
    }

    panic!("Unknown format specifier.")
}

/// Returns an argument vector of detected variable parameters if they are of type string.
pub fn get_variable_number_parameters(
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

    if let Ok(format_string) = format_string_results {
        let parameters =
            parse_format_string_parameters(format_string.as_str(), &project.datatype_properties);
        if parameters.iter().any(|(specifier, _)| is_string(specifier)) {
            return Ok(calculate_parameter_locations(
                project,
                parameters,
                extern_symbol.get_calling_convention(project),
                format_string_index,
            ));
        }

        return Ok(vec![]);
    }

    Err(anyhow!(
        "Could not parse variable parameters: {}",
        format_string_results.unwrap_err()
    ))
}

/// Calculates the register and stack positions of format string parameters.
/// The parameters are then returned as an argument vector for later tainting.
pub fn calculate_parameter_locations(
    project: &Project,
    parameters: Vec<(String, ByteSize)>,
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

    for (type_name, size) in parameters.iter() {
        if is_integer(type_name) || is_pointer(type_name) {
            if integer_arg_register_count > 0 {
                if is_string(type_name) {
                    let register_name = calling_convention.integer_parameter_register
                        [calling_convention.integer_parameter_register.len()
                            - integer_arg_register_count]
                        .clone();
                    var_args.push(create_string_register_arg(
                        project.get_pointer_bytesize(),
                        register_name,
                    ));
                }
                integer_arg_register_count -= 1;
            } else {
                if is_string(type_name) {
                    var_args.push(create_string_stack_arg(*size, stack_offset));
                }
                stack_offset += u64::from(*size) as i64
            }
        } else if float_arg_register_count > 0 {
            float_arg_register_count -= 1;
        } else {
            stack_offset += u64::from(*size) as i64;
        }
    }

    var_args
}

/// Creates a string stack parameter given a size and stack offset.
pub fn create_string_stack_arg(size: ByteSize, stack_offset: i64) -> Arg {
    Arg::Stack {
        offset: stack_offset,
        size,
    }
}

/// Creates a string register parameter given a register name.
pub fn create_string_register_arg(size: ByteSize, register_name: String) -> Arg {
    Arg::Register(Variable {
        name: register_name,
        size,
        is_temp: false,
    })
}

/// Checks whether the format specifier is of type int.
pub fn is_integer(specifier: &str) -> bool {
    matches!(specifier, "d" | "i" | "o" | "x" | "X" | "u" | "c" | "C")
}

/// Checks whether the format specifier is of type pointer.
pub fn is_pointer(specifier: &str) -> bool {
    matches!(specifier, "s" | "S" | "n" | "p")
}

/// Checks whether the format specifier is of type float.
pub fn is_float(specifier: &str) -> bool {
    matches!(specifier, "f" | "F" | "e" | "E" | "a" | "A" | "g" | "G")
}

/// Checks whether the format specifier is a string pointer
/// or a string.
pub fn is_string(specifier: &str) -> bool {
    matches!(specifier, "s" | "S")
}

#[cfg(test)]
mod tests;
