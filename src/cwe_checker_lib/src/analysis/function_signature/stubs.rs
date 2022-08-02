use super::State;
use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::BitvectorDomain;
use crate::abstract_domain::DataDomain;
use crate::abstract_domain::SizedDomain;
use crate::intermediate_representation::Project;
use crate::{
    analysis::function_signature::AccessPattern, intermediate_representation::ExternSymbol,
    prelude::*,
};
use std::collections::BTreeMap;

/// Returns a map that maps the names of known extern functions to the access patterns for their parameters.
///
/// The access patterns are ordered in the same order as the parameters
/// (i.e. the first access pattern corresponds to the first parameter and so on).
pub fn generate_param_access_stubs() -> BTreeMap<&'static str, Vec<AccessPattern>> {
    let read = || AccessPattern::new().with_read_flag();
    let deref = || {
        AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag()
    };
    let deref_mut = || {
        AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag()
            .with_mutably_dereferenced_flag()
    };

    BTreeMap::from([
        ("abort", vec![]),
        ("atoi", vec![deref()]),
        ("bind", vec![read(), deref(), read()]),
        ("calloc", vec![read(), read()]),
        ("close", vec![read()]),
        ("connect", vec![read(), deref(), read()]),
        ("exit", vec![read()]),
        ("fclose", vec![deref_mut()]),
        ("fflush", vec![deref_mut()]),
        ("fgets", vec![deref_mut(), read(), deref_mut()]),
        ("fopen", vec![deref(), deref()]),
        ("fork", vec![]),
        ("fprintf", vec![deref_mut(), deref()]),
        ("fputc", vec![read(), deref_mut()]),
        ("fputs", vec![deref(), deref_mut()]),
        ("fread", vec![deref_mut(), read(), read(), deref_mut()]),
        ("free", vec![deref_mut()]),
        ("fwrite", vec![deref(), read(), read(), deref_mut()]),
        ("getenv", vec![deref()]), // FIXME: Not exactly allocating, but still returns a pointer to another memory region.
        ("getpid", vec![]),
        ("getppid", vec![]),
        ("gettimeofday", vec![deref_mut(), deref_mut()]),
        ("kill", vec![read(), read()]),
        ("localtime", vec![deref()]), // FIXME: The return value is a pointer to static storage.
        ("malloc", vec![read()]),
        ("memcmp", vec![deref(), deref(), read()]),
        ("memcpy", vec![deref_mut(), deref(), read()]),
        ("memmove", vec![deref_mut(), deref(), read()]),
        ("memset", vec![deref_mut(), read(), read()]),
        ("open", vec![deref(), read(), read()]),
        ("open64", vec![deref(), read(), read()]),
        ("perror", vec![deref()]),
        ("printf", vec![deref()]),
        ("putchar", vec![read()]),
        ("puts", vec![deref()]),
        ("qsort", vec![deref_mut(), read(), read(), deref()]),
        ("raise", vec![]),
        ("read", vec![read(), deref_mut(), read()]),
        ("realloc", vec![deref_mut(), read()]),
        ("recv", vec![read(), deref_mut(), read(), read()]),
        (
            "recvfrom",
            vec![
                read(),
                deref_mut(),
                read(),
                read(),
                deref_mut(),
                deref_mut(),
            ],
        ),
        (
            "select",
            vec![read(), deref_mut(), deref_mut(), deref_mut(), deref()],
        ),
        (
            "sendto",
            vec![read(), deref(), read(), read(), deref(), read()],
        ),
        (
            "setsockopt",
            vec![read(), read(), read(), deref_mut(), read()],
        ), // FIXME: The deref_mut parameter may only be deref?
        ("signal", vec![read(), read()]),
        ("sleep", vec![read()]),
        ("snprintf", vec![deref_mut(), read(), deref()]),
        ("socket", vec![read(), read(), read()]),
        ("sprintf", vec![deref_mut(), deref()]),
        ("sscanf", vec![deref(), deref()]),
        ("strcasecmp", vec![deref(), deref()]),
        ("strcat", vec![deref_mut(), deref()]),
        ("strchr", vec![deref(), read()]),
        ("strcmp", vec![deref(), deref()]),
        ("strcpy", vec![deref_mut(), deref()]),
        ("strdup", vec![deref()]),
        ("strerror", vec![read()]),
        ("strlen", vec![deref()]),
        ("strncasecmp", vec![deref(), deref(), read()]),
        ("strncat", vec![deref_mut(), deref(), read()]),
        ("strncmp", vec![deref(), deref(), read()]),
        ("strncpy", vec![deref_mut(), deref(), read()]),
        ("strrchr", vec![deref(), read()]),
        ("strstr", vec![deref(), deref()]),
        ("strtol", vec![deref(), deref_mut(), read()]), // FIXME: We could specify the value written to the second parameter.
        ("strtoul", vec![deref(), deref_mut(), read()]), // FIXME: We could specify the value written to the second parameter.
        ("system", vec![deref()]),
        ("time", vec![deref_mut()]),
        ("unlink", vec![deref()]),
        ("vfprintf", vec![deref_mut(), deref(), deref()]),
        ("write", vec![read(), deref(), read()]),
    ])
}

/// Return a map that maps names of stubbed variadic symbols to a tuple consisting of:
/// - the index of the format string parameter of the symbol
/// - the index of the first variadic parameter (if at least one variadic parameter is used)
/// - the access pattern that the called symbols uses to access its variadic parameters.
/// Note that the access pattern may vary between variadic parameters,
/// e.g. some parameters may only be read and not derefenced by a call to `printf`.
/// But we still approximate all accesses by the the maximal possible access to these parameters.
pub fn get_stubbed_variadic_symbols() -> BTreeMap<&'static str, (usize, usize, AccessPattern)> {
    let deref = || {
        AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag()
    };
    let deref_mut = || {
        AccessPattern::new()
            .with_read_flag()
            .with_dereference_flag()
            .with_mutably_dereferenced_flag()
    };
    BTreeMap::from([
        ("fprintf", (1, 2, deref())),
        ("printf", (0, 1, deref())),
        ("snprintf", (2, 3, deref())),
        ("sprintf", (1, 2, deref())),
        ("sscanf", (1, 2, deref_mut())),
    ])
}

/// Compute the return value of a call to a known extern symbol from the given state.
///
/// Note that this function needs to be called before non-callee-saved registers are cleared from the state,
/// since the return value is usually computed out of the parameter values.
///
/// This function should only be called for symbols contained in the list returned by [generate_param_access_stubs],
/// since it assumes untracked return values (e.g. integers or void) for all not explicitly handled symbols.
pub fn compute_return_value_for_stubbed_function(
    project: &Project,
    state: &mut State,
    extern_symbol: &ExternSymbol,
    call_tid: &Tid,
) -> DataDomain<BitvectorDomain> {
    use return_value_stubs::*;
    match extern_symbol.name.as_str() {
        "memcpy" | "memmove" | "memset" | "strcat" | "strcpy" | "strncat" | "strncpy" => {
            copy_param(state, extern_symbol, 0)
        }
        "fgets" => or_null(copy_param(state, extern_symbol, 0)),
        "calloc" | "fopen" | "malloc" | "strdup" => {
            or_null(new_mem_object_id(call_tid, &extern_symbol.return_values[0]))
        }
        "realloc" => or_null(
            copy_param(state, extern_symbol, 0).merge(&new_mem_object_id(
                call_tid,
                &extern_symbol.return_values[0],
            )),
        ),
        "strchr" | "strrchr" | "strstr" => {
            or_null(param_plus_unknown_offset(state, extern_symbol, 0))
        }
        _ => untracked(project.stack_pointer_register.size),
    }
}

/// Helper functions for computing return values for extern symbol calls.
pub mod return_value_stubs {
    use crate::{abstract_domain::AbstractIdentifier, intermediate_representation::Arg};

    use super::*;

    /// An untracked value is just a `Top` value.
    /// It is used for any non-pointer return values.
    pub fn untracked(register_size: ByteSize) -> DataDomain<BitvectorDomain> {
        DataDomain::new_top(register_size)
    }

    /// A return value that is just a copy of a parameter.
    pub fn copy_param(
        state: &mut State,
        extern_symbol: &ExternSymbol,
        param_index: usize,
    ) -> DataDomain<BitvectorDomain> {
        state.eval_parameter_arg(&extern_symbol.parameters[param_index])
    }

    /// A return value that contains a pointer to the start of a new memory object.
    /// The ID of the memory object is given by the return register and the TID of the call instruction.
    pub fn new_mem_object_id(call_tid: &Tid, return_arg: &Arg) -> DataDomain<BitvectorDomain> {
        DataDomain::from_target(
            AbstractIdentifier::from_arg(call_tid, return_arg),
            Bitvector::zero(return_arg.bytesize().into()).into(),
        )
    }

    /// A return value that adds an unknown offset to a given parameter.
    /// E.g. if the parameter is a pointer to a string,
    /// this return value would describe a pointer to an offset inside the string.
    pub fn param_plus_unknown_offset(
        state: &mut State,
        extern_symbol: &ExternSymbol,
        param_index: usize,
    ) -> DataDomain<BitvectorDomain> {
        let param = state.eval_parameter_arg(&extern_symbol.parameters[param_index]);
        param.add_offset(&BitvectorDomain::new_top(param.bytesize()))
    }

    /// The return value may also be zero in addition to its other possible values.
    pub fn or_null(data: DataDomain<BitvectorDomain>) -> DataDomain<BitvectorDomain> {
        data.merge(&Bitvector::zero(data.bytesize().into()).into())
    }
}
