use crate::prelude::*;
use super::{Term, Arg};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    pub tid: Tid,
    pub address: String,
    pub name: String,
    pub calling_convention: Option<String>,
    pub arguments: Vec<Arg>,
}

/*
(** This type represents an external symbol. *)
type extern_symbol = {
  tid : Bap.Std.tid
  ; address : string
  ; name : string
  ; cconv : string option
  ; args : (Bap.Std.Var.t * Bap.Std.Exp.t * Bap.Std.intent option) list;
}
*/

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
