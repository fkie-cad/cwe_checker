use super::{Arg, ArgIntent};
use crate::bil::*;
use crate::intermediate_representation::ExternSymbol as IrExternSymbol;
use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    pub tid: Tid,
    pub address: String,
    pub name: String,
    pub calling_convention: Option<String>,
    pub arguments: Vec<Arg>,
}

impl ExternSymbol {
    /// Returns the return register of an extern symbol.
    /// Returns an error if the function has not exactly one return argument
    /// or if the return argument is not a register.
    pub fn get_unique_return_register(&self) -> Result<&crate::bil::variable::Variable, Error> {
        let return_args: Vec<_> = self
            .arguments
            .iter()
            .filter(|arg| arg.intent.is_output())
            .collect();
        if return_args.len() != 1 {
            return Err(anyhow!(
                "Wrong number of return register: Got {}, expected 1",
                return_args.len()
            ));
        }
        match &return_args[0].location {
            Expression::Var(var) => Ok(var),
            _ => Err(anyhow!("Return location is not a register")),
        }
    }

    /// Returns the parameter expression of an extern symbol.
    /// Returns an error if the function has not exactly one parameter argument.
    pub fn get_unique_parameter(&self) -> Result<&crate::bil::Expression, Error> {
        let param_args: Vec<_> = self
            .arguments
            .iter()
            .filter(|arg| arg.intent.is_input())
            .collect();
        if param_args.len() != 1 {
            return Err(anyhow!(
                "Wrong number of return register: Got {}, expected 1",
                param_args.len()
            ));
        }
        Ok(&param_args[0].location)
    }
}

impl From<ExternSymbol> for IrExternSymbol {
    fn from(symbol: ExternSymbol) -> IrExternSymbol {
        let mut parameters = Vec::new();
        let mut return_values = Vec::new();
        for arg in symbol.arguments.into_iter() {
            if matches!(
                arg.intent,
                ArgIntent::Input | ArgIntent::Both | ArgIntent::Unknown
            ) {
                for ir_arg in arg.clone().into_ir_args() {
                    parameters.push(ir_arg);
                }
            }
            if matches!(
                arg.intent,
                ArgIntent::Output | ArgIntent::Both | ArgIntent::Unknown
            ) {
                for ir_arg in arg.into_ir_args() {
                    return_values.push(ir_arg);
                }
            }
        }
        IrExternSymbol {
            tid: symbol.tid,
            name: symbol.name,
            calling_convention: None, // We do not parse more than one calling convention from BAP at the moment. So we assume everything uses the standard one.
            parameters,
            return_values,
            no_return: false, // Last time I checked BAP had an attribute for non-returning functions, but did not actually set it.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extern_symbol_serialization() {
        let symbol = ExternSymbol {
            tid: Tid::new("Tid"),
            address: "Somewhere".to_string(),
            name: "extern_fn".to_string(),
            calling_convention: Some("cconv".to_string()),
            arguments: Vec::new(),
        };
        let json: String = serde_json::to_string_pretty(&symbol).unwrap();
        println!("{}", json);
        let _symbol: ExternSymbol = serde_json::from_str(&json).unwrap();
    }
}
