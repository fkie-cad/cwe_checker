use crate::prelude::*;

/// A CWE warning message.
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

impl CweWarning {
    /// Creates a new CweWarning by only setting name, version and description
    pub fn new(name: String, version: String, description: String) -> CweWarning {
        CweWarning {
            name,
            version,
            addresses: Vec::new(),
            tids: Vec::new(),
            symbols: Vec::new(),
            other: Vec::new(),
            description,
        }
    }

    /// Sets the address field of the CweWarning
    pub fn addresses(mut self, addresses: Vec<String>) -> CweWarning {
        self.addresses = addresses;
        self
    }

    /// Sets the Tids field of the CweWarning
    pub fn tids(mut self, tids: Vec<String>) -> CweWarning {
        self.tids = tids;
        self
    }

    /// Sets the symbols field of the CweWarning
    pub fn symbols(mut self, symbols: Vec<String>) -> CweWarning {
        self.symbols = symbols;
        self
    }

    /// Sets the other field of the CweWarning
    pub fn other(mut self, other: Vec<Vec<String>>) -> CweWarning {
        self.other = other;
        self
    }
}

impl std::fmt::Display for CweWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "[{}] ({}) {}",
            self.name, self.version, self.description
        )
    }
}

/// A generic log message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct LogMessage {
    /// The log message.
    pub text: String,
    /// The severity/type of the log message.
    pub level: LogLevel,
    /// The location inside the binary that the message is related to.
    pub location: Option<Tid>,
    /// The analysis where the message originated.
    pub source: Option<String>,
}

impl LogMessage {
    /// Create a new `Info`-level log message
    pub fn new_info(text: impl Into<String>) -> LogMessage {
        LogMessage {
            text: text.into(),
            level: LogLevel::Info,
            location: None,
            source: None,
        }
    }

    /// Create a new `Debug`-level log message
    pub fn new_debug(text: impl Into<String>) -> LogMessage {
        LogMessage {
            text: text.into(),
            level: LogLevel::Debug,
            location: None,
            source: None,
        }
    }

    /// Create a new `Error`-level log message
    pub fn new_error(text: impl Into<String>) -> LogMessage {
        LogMessage {
            text: text.into(),
            level: LogLevel::Error,
            location: None,
            source: None,
        }
    }

    /// Associate a specific location to the log message.
    pub fn location(mut self, location: Tid) -> LogMessage {
        self.location = Some(location);
        self
    }

    /// Set the name of the source analysis for the log message.
    pub fn source(mut self, source: impl Into<String>) -> LogMessage {
        self.source = Some(source.into());
        self
    }
}

/// The severity/type of a log message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum LogLevel {
    /// Messages intended for debugging.
    Debug,
    /// Errors encountered during analysis.
    Error,
    /// Non-error messages intended for the user.
    Info,
}

impl std::fmt::Display for LogMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.level {
            LogLevel::Debug => write!(formatter, "DEBUG: ")?,
            LogLevel::Error => write!(formatter, "ERROR: ")?,
            LogLevel::Info => write!(formatter, "INFO: ")?,
        };
        match (&self.source, &self.location) {
            (Some(source), Some(location)) => write!(formatter, "{} @ {}: ", source, location)?,
            (Some(source), None) => write!(formatter, "{}: ", source)?,
            (None, Some(location)) => write!(formatter, "{}: ", location)?,
            (None, None) => (),
        };
        write!(formatter, "{}", self.text)
    }
}

/// Print all provided log- and CWE-messages.
///
/// Log-messages will always be printed to `stdout`.
/// CWE-warnings will either be printed to `stdout` or to the file path provided in `out_path`.
///
/// If `emit_json` is set, the CWE-warnings will be converted to json for the output.
pub fn print_all_messages(
    logs: Vec<LogMessage>,
    cwes: Vec<CweWarning>,
    out_path: Option<&str>,
    emit_json: bool,
) {
    for log in logs {
        println!("{}", log);
    }
    let output: String = if emit_json {
        serde_json::to_string_pretty(&cwes).unwrap()
    } else {
        cwes.iter()
            .map(|cwe| format!("{}", cwe))
            .collect::<Vec<String>>()
            .join("\n")
            + "\n"
    };
    if let Some(file_path) = out_path {
        std::fs::write(file_path, output).unwrap();
    } else {
        print!("{}", output);
    }
}
