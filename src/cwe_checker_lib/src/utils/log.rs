//! Structs and functions for generating log messages and CWE warnings.

use crate::prelude::*;
use std::{collections::BTreeMap, thread::JoinHandle};

/// A CWE warning message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord, Default)]
pub struct CweWarning {
    /// A short name of the CWE check, e.g. `CWE190`.
    pub name: String,
    /// The version number of the check.
    pub version: String,
    /// Addresses in the binary associated with the CWE warning.
    /// The first address usually denotes the program point where the CWE warning was generated.
    pub addresses: Vec<String>,
    /// Term IDs associated to the CWE warning.
    /// May be more exact than the addresses, e.g. for `Def` terms.
    pub tids: Vec<String>,
    /// Symbol names (usually of extern symbols) associated to the CWE warning.
    pub symbols: Vec<String>,
    /// Other useful information. Content depends on the check that generated the CWE warning.
    pub other: Vec<Vec<String>>,
    /// A short description of the warning that is presented to the user.
    /// Should contain all essential information necessary to understand the warning,
    /// including the address in the binary for which the warning was generated.
    pub description: String,
}

impl CweWarning {
    /// Creates a new CweWarning by only setting name, version and description
    pub fn new(
        name: impl ToString,
        version: impl ToString,
        description: impl ToString,
    ) -> CweWarning {
        CweWarning {
            name: name.to_string(),
            version: version.to_string(),
            addresses: Vec::new(),
            tids: Vec::new(),
            symbols: Vec::new(),
            other: Vec::new(),
            description: description.to_string(),
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
        std::fs::write(file_path, output).unwrap_or_else(|error| {
            panic!("Writing to output path {} failed: {}", file_path, error)
        });
    } else {
        print!("{}", output);
    }
}

/// For each analysis count the number of debug log messages in `all_logs`
/// and add a (INFO level) log message with the resulting number to `all_logs`.
/// Also count and log the number of general debug log messages.
pub fn add_debug_log_statistics(all_logs: &mut Vec<LogMessage>) {
    let mut analysis_debug_log_count = BTreeMap::new();
    let mut general_debug_log_count = 0u64;
    for log in all_logs.iter().filter(|log| log.level == LogLevel::Debug) {
        if let Some(analysis) = &log.source {
            analysis_debug_log_count
                .entry(analysis.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1u64);
        } else {
            general_debug_log_count += 1;
        }
    }
    for (analysis, count) in analysis_debug_log_count {
        all_logs.push(LogMessage {
            text: format!("Logged {} debug log messages.", count),
            level: LogLevel::Info,
            location: None,
            source: Some(analysis),
        });
    }
    if general_debug_log_count > 0 {
        all_logs.push(LogMessage {
            text: format!(
                "Logged {} general debug log messages.",
                general_debug_log_count
            ),
            level: LogLevel::Info,
            location: None,
            source: None,
        });
    }
}

/// The message types a logging thread can receive.
/// See the [`LogThread`] type for more information.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub enum LogThreadMsg {
    /// A normal log message.
    Log(LogMessage),
    /// A CWE warning
    Cwe(CweWarning),
    /// If the log collector thread receives this signal,
    /// it should stop receiving new messages
    /// and instead terminate and return the collected messages prior to receiving the termination signal.
    Terminate,
}

impl From<LogMessage> for LogThreadMsg {
    fn from(msg: LogMessage) -> Self {
        Self::Log(msg)
    }
}

impl From<CweWarning> for LogThreadMsg {
    fn from(warning: CweWarning) -> Self {
        Self::Cwe(warning)
    }
}

/// A type for managing threads for collecting log messages.
///
/// With [`LogThread::spawn()`] one can create a new log thread
/// whose handle is contained in the returned `LogThread` struct.
/// By calling the [`collect()`](LogThread::collect()) method
/// one can tell the log thread to shut down
/// and return the logs collected to this point.
/// If the `LogThread` object gets dropped before calling `collect()`,
/// the corresponding logging thread will be stopped
/// and all collected logs will be discarded.
///
/// If one deliberately wants to discard all logging messages,
/// one can simply create a sender to a disconnected channel
/// via [`LogThread::create_disconnected_sender()`].
pub struct LogThread {
    msg_sender: crossbeam_channel::Sender<LogThreadMsg>,
    thread_handle: Option<JoinHandle<(Vec<LogMessage>, Vec<CweWarning>)>>,
}

impl Drop for LogThread {
    /// If the logging thread still exists,
    /// send it the `Terminate` signal.
    /// Then wait until the logging thread stopped.
    fn drop(&mut self) {
        // Make sure the logging thread gets terminated when dropping this.
        let _ = self.msg_sender.send(LogThreadMsg::Terminate);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl LogThread {
    /// Create a new `LogThread` object with a handle to a freshly spawned logging collector thread.
    ///
    /// The parameter is the function containing the actual log collection logic.
    /// I.e. the function should receive messages through the given receiver until the channel disconnects
    /// or until it receives a [`LogThreadMsg::Terminate`] message.
    /// After that it should return the logs collected up to that point.
    ///
    /// See [`LogThread::collect_and_deduplicate`] for a standard collector function that can be used here.
    pub fn spawn<F>(collector_func: F) -> LogThread
    where
        F: FnOnce(crossbeam_channel::Receiver<LogThreadMsg>) -> (Vec<LogMessage>, Vec<CweWarning>)
            + Send
            + 'static,
    {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let thread_handle = std::thread::spawn(move || collector_func(receiver));
        LogThread {
            msg_sender: sender,
            thread_handle: Some(thread_handle),
        }
    }

    /// Just create a disconnected sender to a (non-existing) logging thread.
    /// Can be used like a sender to a channel that deliberately discards all messages sent to it.
    pub fn create_disconnected_sender() -> crossbeam_channel::Sender<LogThreadMsg> {
        let (sender, _) = crossbeam_channel::unbounded();
        sender
    }

    /// Get a sender that can be used to send messages to the logging thread corresponding to this `LogThread` instance.
    pub fn get_msg_sender(&self) -> crossbeam_channel::Sender<LogThreadMsg> {
        self.msg_sender.clone()
    }

    /// Stop the logging thread by sending it the `Terminate` signal
    /// and then return all logs collected until that point.
    pub fn collect(mut self) -> (Vec<LogMessage>, Vec<CweWarning>) {
        let _ = self.msg_sender.send(LogThreadMsg::Terminate);
        if let Some(handle) = self.thread_handle.take() {
            handle.join().unwrap()
        } else {
            (Vec::new(), Vec::new())
        }
    }

    /// This function is collects logs from the given receiver until a [`LogThreadMsg::Terminate`] signal is received.
    /// All collected logs are deduplicated before being returned.
    ///
    /// CWE warnings and log messages are deduplicated if two messages share the same address of origin.
    /// In such a case only the last message received is kept.
    /// If a CWE message has more than one address only the first address is considered when deduplicating.
    /// Note that this may lead to information loss if log messages with the same origin address that are not duplicates are generated.
    ///
    /// This function can be used as a standard collector function for [`LogThread::spawn`].
    pub fn collect_and_deduplicate(
        receiver: crossbeam_channel::Receiver<LogThreadMsg>,
    ) -> (Vec<LogMessage>, Vec<CweWarning>) {
        let mut logs_with_address = BTreeMap::new();
        let mut general_logs = Vec::new();
        let mut collected_cwes = BTreeMap::new();

        while let Ok(log_thread_msg) = receiver.recv() {
            match log_thread_msg {
                LogThreadMsg::Log(log_message) => {
                    if let Some(ref tid) = log_message.location {
                        logs_with_address.insert(tid.address.clone(), log_message);
                    } else {
                        general_logs.push(log_message);
                    }
                }
                LogThreadMsg::Cwe(cwe_warning) => match &cwe_warning.addresses[..] {
                    [] => panic!("Unexpected CWE warning without origin address"),
                    [address, ..] => {
                        collected_cwes.insert(address.clone(), cwe_warning);
                    }
                },
                LogThreadMsg::Terminate => break,
            }
        }
        let logs = logs_with_address
            .values()
            .cloned()
            .chain(general_logs.into_iter())
            .collect();
        let cwes = collected_cwes.into_values().collect();
        (logs, cwes)
    }
}
