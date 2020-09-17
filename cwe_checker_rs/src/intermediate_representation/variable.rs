use crate::prelude::*;
use super::ByteSize;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
  pub name: String,
  pub size: ByteSize,
  pub is_temp: bool,
}