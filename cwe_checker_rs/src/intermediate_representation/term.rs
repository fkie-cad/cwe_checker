use crate::prelude::*;
use crate::term::{Term, Tid};
use super::{Variable, Expression, ByteSize};



#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Def {
    Load {
        var: Variable,
        address: Expression,
    },
    Store {
        address: Expression,
        value: Expression,
    },
    Assign {
        var: Variable,
        value: Expression,
    },
}