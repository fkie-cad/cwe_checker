use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord, Default)]
pub struct CweWarning {
    pub name: String,
    pub version: String,
    pub addresses: Vec<String>,
    pub tids: Vec<String>,
    pub symbols: Vec<String>,
    pub other: Vec<Vec<String>>,
    pub description: String
}
