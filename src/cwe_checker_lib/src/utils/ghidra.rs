//! Utility functions for executing Ghidra and extracting P-Code from the output.

use crate::ghidra_pcode::PcodeProject;
use crate::prelude::*;
use crate::utils::binary::BareMetalConfig;
use crate::utils::{get_ghidra_plugin_path, read_config_file};
use crate::{
    intermediate_representation::Project,
    utils::debug,
    utils::log::LogMessage,
};

use directories::ProjectDirs;
use nix::{sys::stat, unistd};

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

/// Execute the `p_code_extractor` plugin in Ghidra and parse its output into the `Project` data structure.
///
/// Return an error if the creation of the project failed.
pub fn get_project_from_ghidra(
    file_path: &Path,
    binary: &[u8],
    bare_metal_config_opt: Option<BareMetalConfig>,
    debug_settings: &debug::Settings,
) -> Result<(Project, Vec<LogMessage>), Error> {
    let pcode_project = if let Some(saved_pcode_raw) = debug_settings.get_saved_pcode_raw() {
        let file = std::fs::File::open(saved_pcode_raw)
            .expect("Failed to open saved output of Pcode Extractor plugin.");
        serde_json::from_reader(std::io::BufReader::new(file))?
    } else {
        let tmp_folder = get_tmp_folder()?;
        // We add a timestamp suffix to file names
        // so that if two instances of the cwe_checker are running in parallel on the same file
        // they do not interfere with each other.
        let timestamp_suffix = format!(
            "{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        // Create a unique name for the pipe
        let fifo_path = tmp_folder.join(format!("pcode_{timestamp_suffix}.pipe"));
        let ghidra_command = generate_ghidra_call_command(
            file_path,
            &fifo_path,
            &timestamp_suffix,
            &bare_metal_config_opt,
        )?;
        execute_ghidra(ghidra_command, &fifo_path, debug_settings)?
    };

    parse_pcode_project_to_ir_project(pcode_project, binary, &bare_metal_config_opt)
}

/// Normalize the given P-Code project
/// and then parse it into a project struct of the internally used intermediate representation.
pub fn parse_pcode_project_to_ir_project(
    pcode_project: PcodeProject,
    _binary: &[u8],
    bare_metal_config_opt: &Option<BareMetalConfig>,
) -> Result<(Project, Vec<LogMessage>), Error> {
    let _bare_metal_base_address_opt = bare_metal_config_opt
        .as_ref()
        .map(|config| config.parse_binary_base_address());
    let project = pcode_project.into_ir_project();
    let log_messages = vec![];

    Ok((project, log_messages))
}

/// Execute Ghidra with the P-Code plugin and return the parsed P-Code project.
///
/// Note that this function will abort the program if the Ghidra execution does not succeed.
fn execute_ghidra(
    mut ghidra_command: Command,
    fifo_path: &PathBuf,
    debug_settings: &debug::Settings,
) -> Result<PcodeProject, Error> {
    let should_print_ghidra_error = debug_settings.verbose();
    // Create a new fifo and give read and write rights to the owner
    unistd::mkfifo(fifo_path, stat::Mode::from_bits(0o600).unwrap())
        .context("Error creating FIFO pipe")?;
    // Execute Ghidra in a new thread and return a Join Handle, so that the thread is only joined
    // after the output has been read into the cwe_checker
    let ghidra_subprocess = thread::spawn(move || {
        // Execute the command and catch its output.
        let output = match ghidra_command.output() {
            Ok(output) => output,
            Err(err) => {
                eprintln!("Ghidra could not be executed: {err}");
                std::process::exit(101);
            }
        };

        if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
            if stdout.contains("Pcode was successfully extracted!") && output.status.success() {
                return;
            }
        }
        if should_print_ghidra_error {
            eprintln!("{}", String::from_utf8(output.stdout).unwrap());
            eprintln!("{}", String::from_utf8(output.stderr).unwrap());
            if let Some(code) = output.status.code() {
                eprintln!("Ghidra plugin failed with exit code {code}");
            }
            eprintln!("Execution of Ghidra plugin failed.");
        } else {
            eprintln!("Execution of Ghidra plugin failed. Use the --verbose flag to print Ghidra output for troubleshooting.");
        }
        std::process::exit(101)
    });

    // Open the FIFO
    let mut file = std::fs::File::open(fifo_path.clone()).expect("Could not open FIFO.");
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("Error while reading from FIFO.");
    debug_settings.print(&buf, debug::Stage::Pcode(debug::PcodeForm::Raw));
    let pcode_parsing_result = serde_json::from_str(&buf);

    ghidra_subprocess
        .join()
        .expect("The Ghidra thread to be joined has panicked!");
    // Clean up the FIFO pipe and propagate errors from the JSON parsing.
    std::fs::remove_file(fifo_path).context("Could not clean up FIFO pipe")?;
    Ok(pcode_parsing_result?)
}

/// Generate the command that is used to call Ghidra and execute the P-Code-Extractor plugin in it.
fn generate_ghidra_call_command(
    file_path: &Path,
    fifo_path: &Path,
    timestamp_suffix: &str,
    bare_metal_config_opt: &Option<BareMetalConfig>,
) -> Result<Command, Error> {
    let ghidra_path: std::path::PathBuf =
        serde_json::from_value(read_config_file("ghidra.json")?["ghidra_path"].clone())
            .context("Path to Ghidra not configured.")?;
    let headless_path = ghidra_path.join("support/analyzeHeadless");
    let tmp_folder = get_tmp_folder()?;
    let filename = file_path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_string_lossy()
        .to_string();
    let ghidra_plugin_path = get_ghidra_plugin_path("p_code_extractor");

    let mut ghidra_command = Command::new(headless_path);
    ghidra_command
        .arg(&tmp_folder) // The folder where temporary files should be stored
        .arg(format!("PcodeExtractor_{filename}_{timestamp_suffix}")) // The name of the temporary Ghidra Project.
        .arg("-import") // Import a file into the Ghidra project
        .arg(file_path) // File import path
        .arg("-postScript") // Execute a script after standard analysis by Ghidra finished
        .arg(ghidra_plugin_path.join("PcodeExtractor.java")) // Path to the PcodeExtractor.java
        .arg(fifo_path) // The path to the named pipe (fifo)
        .arg("-scriptPath") // Add a folder containing additional script files to the Ghidra script file search paths
        .arg(ghidra_plugin_path) // Path to the folder containing the PcodeExtractor.java (so that the other java files can be found.)
        .arg("-deleteProject") // Delete the temporary project after the script finished
        .arg("-analysisTimeoutPerFile") // Set a timeout for how long the standard analysis can run before getting aborted
        .arg("3600"); // Timeout of one hour (=3600 seconds) // TODO: The post-script can detect that the timeout fired and react accordingly.
    if let Some(bare_metal_config) = bare_metal_config_opt {
        let mut base_address: &str = &bare_metal_config.flash_base_address;
        if let Some(stripped_address) = base_address.strip_prefix("0x") {
            base_address = stripped_address;
        }
        ghidra_command
            .arg("-loader") // Tell Ghidra to use a specific loader
            .arg("BinaryLoader") // Use the BinaryLoader for bare metal binaries
            .arg("-loader-baseAddr") // Provide the base address where the binary should be mapped in memory
            .arg(base_address)
            .arg("-processor") // Provide the processor type ID, for which the binary was compiled.
            .arg(bare_metal_config.processor_id.clone());
    }

    Ok(ghidra_command)
}

/// Get the folder where temporary files should be stored for the program.
fn get_tmp_folder() -> Result<PathBuf, Error> {
    let project_dirs = ProjectDirs::from("", "", "cwe_checker")
        .context("Could not determine path for temporary files")?;
    let tmp_folder = if let Some(folder) = project_dirs.runtime_dir() {
        folder
    } else {
        Path::new("/tmp/cwe_checker")
    };
    if !tmp_folder.exists() {
        std::fs::create_dir(tmp_folder).context("Unable to create temporary folder")?;
    }
    Ok(tmp_folder.to_path_buf())
}
