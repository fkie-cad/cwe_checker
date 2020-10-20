pub mod log;

/// Get the names of parameter registers and callee saved registers
/// of the standard calling convention for the given architecture.
///
/// The registers are read from a configuration file.
pub fn get_generic_parameter_and_callee_saved_register(
    cpu_architecture: &str,
) -> (Vec<String>, Vec<String>) {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .expect("Could not discern location of configuration files.");
    let config_dir = project_dirs.config_dir();
    let register_config_path = config_dir.join("registers.json");
    let file = std::fs::read_to_string(register_config_path)
        .expect("Could not read register configuration file");
    let mut registers_json: serde_json::Value = serde_json::from_str(&file).unwrap();
    match cpu_architecture {
        "x86" | "x86_32" => registers_json = registers_json["elf"]["x86"]["cdecl"].clone(),
        "ARM_32" => registers_json = registers_json["elf"]["armv7"].clone(),
        _ => registers_json = registers_json["elf"][cpu_architecture].clone(),
    }
    let mut callee_saved: Vec<String> =
        serde_json::from_value(registers_json["callee_saved"].clone()).unwrap();
    let mut callee_saved_float: Vec<String> =
        serde_json::from_value(registers_json["float_callee_saved"].clone()).unwrap();
    callee_saved.append(&mut callee_saved_float);
    let mut params: Vec<String> = serde_json::from_value(registers_json["params"].clone()).unwrap();
    let mut params_float: Vec<String> =
        serde_json::from_value(registers_json["float_params"].clone()).unwrap();
    params.append(&mut params_float);
    (params, callee_saved)
}

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
