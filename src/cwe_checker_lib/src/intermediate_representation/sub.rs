use super::{Blk, Datatype, Expression, Project, Variable};
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
    /// The calling convention used to call if known
    pub calling_convention: Option<String>,
}

/// A parameter or return argument of a function.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Arg {
    /// The argument is passed in a register
    Register {
        /// The expression evaluating to the argument.
        expr: Expression,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
    /// The argument is passed on the stack.
    Stack {
        /// The expression that computes the address of the argument on the stack.
        address: Expression,
        /// The size in bytes of the argument.
        size: ByteSize,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
}

impl Arg {
    /// Generate a new register argument.
    pub fn from_var(var: Variable, data_type_hint: Option<Datatype>) -> Arg {
        Arg::Register {
            expr: Expression::Var(var),
            data_type: data_type_hint,
        }
    }

    /// Returns the data type field of an Arg object.
    pub fn get_data_type(&self) -> Option<Datatype> {
        match self {
            Arg::Register { data_type, .. } => data_type.clone(),
            Arg::Stack { data_type, .. } => data_type.clone(),
        }
    }

    /// If the argument is a stack argument,
    /// return its offset relative to the current stack register value.
    /// Return an error for register arguments or if the offset could not be computed.
    pub fn eval_stack_offset(&self) -> Result<Bitvector, Error> {
        let expression = match self {
            Arg::Register { .. } => return Err(anyhow!("The argument is not a stack argument.")),
            Arg::Stack { address, .. } => address,
        };
        Self::eval_stack_offset_expression(expression)
    }

    /// If the given expression computes a constant offset to the given stack register,
    /// then return the offset.
    /// Else return an error.
    fn eval_stack_offset_expression(expression: &Expression) -> Result<Bitvector, Error> {
        match expression {
            Expression::Var(var) => Ok(Bitvector::zero(var.size.into())),
            Expression::Const(bitvec) => Ok(bitvec.clone()),
            Expression::BinOp { op, lhs, rhs } => {
                let lhs = Self::eval_stack_offset_expression(lhs)?;
                let rhs = Self::eval_stack_offset_expression(rhs)?;
                lhs.bin_op(*op, &rhs)
            }
            Expression::UnOp { op, arg } => {
                let arg = Self::eval_stack_offset_expression(arg)?;
                arg.un_op(*op)
            }
            _ => Err(anyhow!("Expression type not supported for argument values")),
        }
    }

    /// Return the bytesize of the argument.
    pub fn bytesize(&self) -> ByteSize {
        match self {
            Arg::Register { expr, .. } => expr.bytesize(),
            Arg::Stack { size, .. } => *size,
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
                Arg::Register {
                    expr: Expression::Var(ref var),
                    ..
                } => Ok(var),
                Arg::Register { .. } => Err(anyhow!("Return value is a sub-register")),
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
    pub integer_parameter_register: Vec<Variable>,
    /// Possible float parameter registers.
    /// Given as expressions, since they are usually sub-register of larger floating point registers.
    pub float_parameter_register: Vec<Expression>,
    /// A list of possible return register for non-float values.
    pub integer_return_register: Vec<Variable>,
    /// A list of possible return register for float values.
    /// Given as expressions, since they are usually sub-register of larger floating point registers.
    pub float_return_register: Vec<Expression>,
    /// A list of callee-saved register,
    /// i.e. the values of these registers should be the same after the call as they were before the call.
    pub callee_saved_register: Vec<Variable>,
}

impl CallingConvention {
    /// Return a list of all parameter registers of the calling convention.
    /// For parameters, where only a part of a register is the actual parameter,
    /// the parameter register is approximated by the (larger) base register.
    pub fn get_all_parameter_register(&self) -> Vec<&Variable> {
        let mut register_list: Vec<&Variable> = self.integer_parameter_register.iter().collect();
        for float_param_expr in self.float_parameter_register.iter() {
            register_list.append(&mut float_param_expr.input_vars());
        }
        register_list
    }

    /// Return a list of all return registers of the calling convention.
    /// For return register, where only a part of a register is the actual return register,
    /// the return register is approximated by the (larger) base register.
    pub fn get_all_return_register(&self) -> Vec<&Variable> {
        let mut register_list: Vec<&Variable> = self.integer_return_register.iter().collect();
        for float_param_expr in self.float_return_register.iter() {
            register_list.append(&mut float_param_expr.input_vars());
        }
        register_list
    }
}
