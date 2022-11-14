//! Handles argument detection by parsing format string arguments during a function call. (e.g. sprintf)

use crate::prelude::*;
use crate::{
    abstract_domain::TryToBitvec, analysis::pointer_inference::State as PointerInferenceState,
    intermediate_representation::*,
};
use regex::Regex;
use std::collections::HashMap;

/// Parses the input format string for the corresponding string function.
pub fn get_input_format_string(
    pi_state: &PointerInferenceState,
    extern_symbol: &ExternSymbol,
    format_string_index: usize,
    runtime_memory_image: &RuntimeMemoryImage,
) -> Result<String, Error> {
    if let Some(format_string) = extern_symbol.parameters.get(format_string_index) {
        if let Ok(Some(address)) = pi_state
            .eval_parameter_arg(format_string, runtime_memory_image)
            .as_ref()
            .map(|param| param.get_if_absolute_value())
        {
            let address = address.try_to_bitvec()?;
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
    address: Bitvector,
    runtime_memory_image: &RuntimeMemoryImage,
) -> Result<String, Error> {
    match runtime_memory_image.read_string_until_null_terminator(&address) {
        Ok(format_string) => Ok(format_string.to_string()),
        Err(e) => Err(anyhow!("{}", e)),
    }
}

/// Parses the format string parameters using a regex, determines their data types,
/// and calculates their positions (register or memory).
pub fn parse_format_string_parameters(
    format_string: &str,
    datatype_properties: &DatatypeProperties,
) -> Result<Vec<(Datatype, ByteSize)>, Error> {
    // Regex parts:
    // - `%` starts a format string parameter
    // - `[+\-#0]{0,1}` matches the flags `+`, `-`, `#`, `0` if present (for printf-like functions)
    // - `\d*` matches the width parameter
    // - `[\.]?\d*` matches the precision parameter (for printf-like functions)
    // - `[cCdiouxXeEfFgGaAnpsS]` matches a format specifier without length parameter.
    // - `hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA` matches format specifiers with length parameter.
    let re = Regex::new(r#"%[+\-#0]{0,1}\d*[\.]?\d*([cCdiouxXeEfFgGaAnpsS]|hi|hd|hu|li|ld|lu|lli|lld|llu|lf|lg|le|la|lF|lG|lE|lA|Lf|Lg|Le|La|LF|LG|LE|LA)"#)
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

/// Returns an argument vector of detected variable parameters.
pub fn get_variable_parameters(
    project: &Project,
    pi_state: &PointerInferenceState,
    extern_symbol: &ExternSymbol,
    format_string_index_map: &HashMap<String, usize>,
) -> Result<Vec<Arg>, Error> {
    let format_string_index = match format_string_index_map.get(&extern_symbol.name) {
        Some(index) => *index,
        None => panic!("External Symbol does not contain a format string parameter."),
    };

    let format_string_results = get_input_format_string(
        pi_state,
        extern_symbol,
        format_string_index,
        &project.runtime_memory_image,
    );

    if let Ok(format_string) = format_string_results.as_ref() {
        let parameter_result =
            parse_format_string_parameters(format_string, &project.datatype_properties);
        match parameter_result {
            Ok(parameters) => {
                return Ok(calculate_parameter_locations(
                    parameters,
                    extern_symbol,
                    project,
                ));
            }
            Err(e) => {
                return Err(anyhow!("Could not parse variable parameters: {}", e));
            }
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
    variadic_parameters: Vec<(Datatype, ByteSize)>,
    extern_symbol: &ExternSymbol,
    project: &Project,
) -> Vec<Arg> {
    let calling_convention = project.get_calling_convention(extern_symbol);
    let mut var_args: Vec<Arg> = Vec::new();
    let mut float_arg_register_count = calling_convention.float_parameter_register.len();
    let mut stack_offset: i64 = match project.cpu_architecture.as_str() {
        "x86" | "x86_32" | "x86_64" => u64::from(project.stack_pointer_register.size) as i64,
        _ => 0,
    };
    let mut integer_arg_register_count =
        if calling_convention.integer_parameter_register.len() >= extern_symbol.parameters.len() {
            calling_convention.integer_parameter_register.len() - extern_symbol.parameters.len()
        } else {
            for param in extern_symbol.parameters.iter() {
                if let Ok(offset) = param.eval_stack_offset() {
                    let offset_after = offset.try_to_u64().unwrap() + u64::from(param.bytesize());
                    stack_offset = std::cmp::max(stack_offset, offset_after as i64);
                }
            }
            0
        };

    for (data_type, size) in variadic_parameters.iter() {
        match data_type {
            Datatype::Integer | Datatype::Pointer | Datatype::Char => {
                if integer_arg_register_count > 0 {
                    let register = calling_convention.integer_parameter_register[calling_convention
                        .integer_parameter_register
                        .len()
                        - integer_arg_register_count]
                        .clone();

                    var_args.push(create_register_arg(
                        Expression::Var(register),
                        data_type.clone(),
                    ));

                    integer_arg_register_count -= 1;
                } else {
                    var_args.push(create_stack_arg(
                        *size,
                        stack_offset,
                        data_type.clone(),
                        &project.stack_pointer_register,
                    ));
                    stack_offset += u64::from(*size) as i64
                }
            }
            Datatype::Double => {
                if float_arg_register_count > 0 {
                    let expr = calling_convention.float_parameter_register[calling_convention
                        .float_parameter_register
                        .len()
                        - float_arg_register_count]
                        .clone();

                    var_args.push(create_register_arg(expr, data_type.clone()));

                    float_arg_register_count -= 1;
                } else {
                    var_args.push(create_stack_arg(
                        *size,
                        stack_offset,
                        data_type.clone(),
                        &project.stack_pointer_register,
                    ));
                    stack_offset += u64::from(*size) as i64
                }
            }
            _ => panic!("Invalid data type specifier from format string."),
        }
    }

    var_args
}

/// Creates a stack parameter given a size, stack offset and data type.
fn create_stack_arg(
    size: ByteSize,
    stack_offset: i64,
    data_type: Datatype,
    stack_register: &Variable,
) -> Arg {
    Arg::Stack {
        address: Expression::Var(stack_register.clone()).plus_const(stack_offset),
        size,
        data_type: Some(data_type),
    }
}

/// Creates a register parameter given a size, register name and data type.
fn create_register_arg(expr: Expression, data_type: Datatype) -> Arg {
    Arg::Register {
        expr,
        data_type: Some(data_type),
    }
}

#[cfg(test)]
mod tests;
