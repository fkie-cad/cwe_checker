use super::{Blk, Datatype, Project, Variable};
use crate::prelude::*;

/// A `Sub` or subroutine represents a function with a given name and a list of basic blocks belonging to it.
///
/// Subroutines are *single-entry*,
/// i.e. calling a subroutine will execute the first block in the list of basic blocks.
/// A subroutine may have multiple exits, which are identified by `Jmp::Return` instructions.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    /// The name of the subroutine
    pub name: String,
    /// The basic blocks belonging to the subroutine.
    /// The first block is also the entry point of the subroutine.
    pub blocks: Vec<Term<Blk>>,
}

/// A parameter or return argument of a function.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Arg {
    /// The argument is passed in the given register
    Register {
        /// The variable object representing the register.
        var: Variable,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
    /// The argument is passed on the stack.
    /// It is positioned at the given offset (in bytes) relative to the stack pointer on function entry
    /// and has the given size.
    Stack {
        /// The position of the argument on the stack
        /// given as offset relative to the stack pointer on function entry.
        offset: i64,
        /// The size in bytes of the argument.
        size: ByteSize,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
}

impl Arg {
    /// Returns the data type field of an Arg object.
    pub fn get_data_type(&self) -> Option<Datatype> {
        match self {
            Arg::Register { data_type, .. } => data_type.clone(),
            Arg::Stack { data_type, .. } => data_type.clone(),
        }
    }
}

/// An extern symbol represents a funtion that is dynamically linked from another binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    /// The term ID of the extern symbol.
    pub tid: Tid,
    /// Addresses of possibly multiple locations of the same extern symbol
    pub addresses: Vec<String>,
    /// The name of the extern symbol
    pub name: String,
    /// The calling convention used for the extern symbol if known
    pub calling_convention: Option<String>,
    /// Parameters of an extern symbol.
    /// May be empty if there are no parameters or the parameters are unknown.
    pub parameters: Vec<Arg>,
    /// Return values of an extern symbol.
    /// May be empty if there is no return value or the return values are unknown.
    pub return_values: Vec<Arg>,
    /// If set to `true`, the function is assumed to never return to its caller when called.
    pub no_return: bool,
    /// If the function has a variable number of parameters, this flag is set to `true`.
    pub has_var_args: bool,
}

impl ExternSymbol {
    /// If the extern symbol has exactly one return value that is passed in a register,
    /// return the register.
    pub fn get_unique_return_register(&self) -> Result<&Variable, Error> {
        if self.return_values.len() == 1 {
            match self.return_values[0] {
                Arg::Register { ref var, .. } => Ok(var),
                Arg::Stack { .. } => Err(anyhow!("Return value is passed on the stack")),
            }
        } else {
            Err(anyhow!("Wrong number of return values"))
        }
    }

    /// If the extern symbol has exactly one parameter, return the parameter.
    pub fn get_unique_parameter(&self) -> Result<&Arg, Error> {
        if self.parameters.len() == 1 {
            Ok(&self.parameters[0])
        } else {
            Err(anyhow!("Wrong number of parameter values"))
        }
    }

    /// Get the calling convention corresponding to the extern symbol.
    pub fn get_calling_convention<'a>(&self, project: &'a Project) -> &'a CallingConvention {
        project.get_calling_convention(self)
    }
}

/// Calling convention related data
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConvention {
    /// The name of the calling convention
    #[serde(rename = "calling_convention")]
    pub name: String,
    /// Possible integer parameter registers.
    pub integer_parameter_register: Vec<String>,
    /// Possible float parameter registers.
    pub float_parameter_register: Vec<String>,
    /// A list of possible return register
    pub return_register: Vec<String>,
    /// A list of callee-saved register,
    /// i.e. the values of these registers should be the same after the call as they were before the call.
    pub callee_saved_register: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Sub {
        pub fn mock(name: impl ToString) -> Term<Sub> {
            Term {
                tid: Tid::new(name.to_string()),
                term: Sub {
                    name: name.to_string(),
                    blocks: Vec::new(),
                },
            }
        }
    }

    impl CallingConvention {
        pub fn mock() -> CallingConvention {
            CallingConvention {
                name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
                integer_parameter_register: vec!["RDI".to_string()],
                float_parameter_register: vec!["XMMO".to_string()],
                return_register: vec!["RAX".to_string()],
                callee_saved_register: vec!["RBP".to_string()],
            }
        }

        pub fn mock_with_parameter_registers(
            integer_parameter_register: Vec<String>,
            float_parameter_register: Vec<String>,
        ) -> CallingConvention {
            CallingConvention {
                name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
                integer_parameter_register,
                float_parameter_register,
                return_register: vec!["RAX".to_string()],
                callee_saved_register: vec!["RBP".to_string()],
            }
        }
    }

    impl Arg {
        pub fn mock_register(name: impl ToString, size_in_bytes: impl Into<ByteSize>) -> Arg {
            Arg::Register {
                var: Variable::mock(name.to_string(), size_in_bytes),
                data_type: None,
            }
        }

        pub fn mock_register_with_data_type(
            name: impl ToString,
            size_in_bytes: impl Into<ByteSize>,
            data_type: Option<Datatype>,
        ) -> Arg {
            Arg::Register {
                var: Variable::mock(name.to_string(), size_in_bytes),
                data_type,
            }
        }

        pub fn mock_pointer_register(
            name: impl ToString,
            size_in_bytes: impl Into<ByteSize>,
        ) -> Arg {
            Arg::Register {
                var: Variable::mock(name.to_string(), size_in_bytes),
                data_type: Some(Datatype::Pointer),
            }
        }
    }

    impl ExternSymbol {
        pub fn mock() -> ExternSymbol {
            ExternSymbol {
                tid: Tid::new("mock_symbol"),
                addresses: vec!["UNKNOWN".to_string()],
                name: "mock_symbol".to_string(),
                calling_convention: Some("__stdcall".to_string()),
                parameters: vec![Arg::mock_register("RDI", 8)],
                return_values: vec![Arg::mock_register("RAX", 8)],
                no_return: false,
                has_var_args: false,
            }
        }

        pub fn mock_string() -> Self {
            ExternSymbol {
                tid: Tid::new("sprintf"),
                addresses: vec!["UNKNOWN".to_string()],
                name: "sprintf".to_string(),
                calling_convention: Some("__stdcall".to_string()),
                parameters: vec![Arg::mock_register("RDI", 8), Arg::mock_register("RSI", 8)],
                return_values: vec![Arg::mock_register("RAX", 8)],
                no_return: false,
                has_var_args: true,
            }
        }
    }
}
