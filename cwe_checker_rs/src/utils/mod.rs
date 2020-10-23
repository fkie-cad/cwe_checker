pub mod log;
pub mod symbol_utils;

/// Get the contents of a configuration file.
pub fn read_config_file(filename: &str) -> serde_json::Value {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .expect("Could not discern location of configuration files.");
    let config_dir = project_dirs.config_dir();
    let config_path = config_dir.join(filename);
    let config_file =
        std::fs::read_to_string(config_path).expect("Could not read configuration file");
    serde_json::from_str(&config_file).unwrap()
}

/// Get the folder path to a Ghidra plugin bundled with the cwe_checker.
pub fn get_ghidra_plugin_path(plugin_name: &str) -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .expect("Could not discern location of data directory.");
    let data_dir = project_dirs.data_dir();
    data_dir.join("ghidra").join(plugin_name)
}
