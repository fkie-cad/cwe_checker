//! This module contains various utility modules and helper functions.

pub mod arguments;
pub mod binary;
pub mod debug;
pub mod ghidra;
pub mod graph_utils;
pub mod log;
pub mod symbol_utils;

use crate::prelude::*;

/// Get the contents of a configuration file.
pub fn read_config_file(filename: &str) -> Result<serde_json::Value, Error> {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .context("Could not discern location of configuration files.")?;
    let config_dir = project_dirs.config_dir();
    let config_path = config_dir.join(filename);
    let config_file =
        std::fs::read_to_string(config_path).context("Could not read configuration file")?;
    Ok(serde_json::from_str(&config_file)?)
}

/// Get the folder path to a Ghidra plugin bundled with the cwe_checker.
pub fn get_ghidra_plugin_path(plugin_name: &str) -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .expect("Could not discern location of data directory.");
    let data_dir = project_dirs.data_dir();
    data_dir.join("ghidra").join(plugin_name)
}
