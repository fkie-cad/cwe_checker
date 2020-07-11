use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord, Default)]
pub struct CweWarning {
    pub name: String,
    pub version: String,
    pub addresses: Vec<String>,
    pub tids: Vec<String>,
    pub symbols: Vec<String>,
    pub other: Vec<Vec<String>>,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct LogMessage {
    pub text: String,
    pub level: LogLevel,
    pub location: Option<Tid>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Error,
    Info,
}

impl std::fmt::Display for LogMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref tid) = self.location {
            match self.level {
                LogLevel::Debug => write!(formatter, "Debug: {}: {}", tid.address, self.text),
                LogLevel::Error => write!(formatter, "Error: {}: {}", tid.address, self.text),
                LogLevel::Info => write!(formatter, "Info: {}: {}", tid.address, self.text),
            }
        } else {
            match self.level {
                LogLevel::Debug => write!(formatter, "Debug: {}", self.text),
                LogLevel::Error => write!(formatter, "Error: {}", self.text),
                LogLevel::Info => write!(formatter, "Info: {}", self.text),
            }
        }
    }
}
