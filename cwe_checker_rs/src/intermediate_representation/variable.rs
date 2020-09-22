use super::ByteSize;
use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
    pub name: String,
    pub size: ByteSize,
    pub is_temp: bool,
}
