use super::Arg;
use crate::bil::*;
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
            _ => Err(anyhow!("Return location is not a register"))?,
        }
    }

    /// Returns the parameter register of an extern symbol.
    /// Returns an error if the function has not exactly one parameter argument
    /// or if the parameter argument is not a register.
    pub fn get_unique_parameter_register(&self) -> Result<&crate::bil::variable::Variable, Error> {
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
        match &param_args[0].location {
            Expression::Var(var) => Ok(var),
            _ => Err(anyhow!("Parameter location is not a register"))?,
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
