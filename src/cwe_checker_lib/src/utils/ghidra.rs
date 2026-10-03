//! Utility functions for executing Ghidra and extracting P-Code from the output.

use crate::ghidra_pcode::PcodeProject;
use crate::intermediate_representation::{Project, RuntimeMemoryImage};
use crate::prelude::*;
use crate::utils::binary::BareMetalConfig;
use crate::utils::debug;
use crate::utils::log::{LogMessage, WithLogs};
use crate::utils::{get_ghidra_plugin_path, read_config_file};

use directories::ProjectDirs;
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::ServerOptions,
    process::Command,
};

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Execute the `p_code_extractor` plugin in Ghidra and parse its output into the `Project` data structure.
///
/// Return an error if the creation of the project failed.
pub fn get_project_from_ghidra(
    file_path: &Path,
    binary: &[u8],
    bare_metal_config_opt: Option<BareMetalConfig>,
    debug_settings: &debug::Settings,
) -> Result<WithLogs<Project>, Error> {
    let pcode_project = if let Some(saved_pcode_raw) = debug_settings.get_saved_pcode_raw() {
        let mut file = std::fs::File::open(saved_pcode_raw)
            .expect("Failed to open saved output of Pcode Extractor plugin.");
        let mut saved_pcode_raw = String::new();
        file.read_to_string(&mut saved_pcode_raw)
            .expect("Failed to read saved Pcode Extractor plugin output");
        debug_settings.print(&saved_pcode_raw, debug::Stage::Pcode(debug::PcodeForm::Raw));
        serde_json::from_str(&saved_pcode_raw)?
    } else {
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
        #[cfg(target_os = "linux")]
        let fifo_path ={
            let tmp_folder = get_tmp_folder()?;
            tmp_folder.join(format!("pcode_{timestamp_suffix}.pipe"))
        };
        #[cfg(target_os = "windows")]
        let fifo_path = PathBuf::from(format!(r"\\.\pipe\pcode_{timestamp_suffix}"));
        let ghidra_command = generate_ghidra_call_command(
            file_path,
            &fifo_path,
            &timestamp_suffix,
            &bare_metal_config_opt,
        )?;
        execute_ghidra(ghidra_command, &fifo_path, debug_settings)?
    };
    debug_settings.print(
        &pcode_project,
        debug::Stage::Pcode(debug::PcodeForm::Parsed),
    );

    parse_pcode_project_to_ir_project(
        pcode_project,
        binary,
        &bare_metal_config_opt,
        debug_settings,
    )
}

/// Normalize the given P-Code project and then parse it into a project struct
/// of the internally used intermediate representation.
pub fn parse_pcode_project_to_ir_project(
    pcode_project: PcodeProject,
    binary: &[u8],
    bare_metal_config_opt: &Option<BareMetalConfig>,
    debug_settings: &debug::Settings,
) -> Result<WithLogs<Project>, Error> {
    let bare_metal_base_address_opt = bare_metal_config_opt
        .as_ref()
        .map(|config| config.parse_binary_base_address());

    let project: WithLogs<Project> = match RuntimeMemoryImage::get_base_address(binary) {
        Ok(binary_base_address) => {
            pcode_project.into_ir_project(binary_base_address, debug_settings)
        }
        Err(_err) => {
            if let Some(binary_base_address) = bare_metal_base_address_opt {
                let mut project =
                    pcode_project.into_ir_project(binary_base_address, debug_settings);

                project.program.term.address_base_offset = 0;

                project
            } else {
                let mut project = pcode_project.into_ir_project(0, debug_settings);
                project.add_log_msg(LogMessage::new_info("Could not determine binary base address. Using base address of Ghidra output as fallback."));

                // For PE files setting the address_base_offset to zero is a hack, which worked for the tested PE files.
                // But this hack will probably not work in general!
                project.program.term.address_base_offset = 0;

                project
            }
        }
    };

    Ok(project)
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

    // The function stays sync, so it drives its own runtime.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?;

    runtime.block_on(async {
        // Must be created inside the runtime context so the pipe gets registered with the reactor.
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(fifo_path)
            .context("Failed to create named pipe server")?;

        // If we bail out early, don't leave Ghidra running.
        ghidra_command.kill_on_drop(true);

        // Spawned as a task so it keeps draining stdout/stderr while we read the pipe.
        let mut ghidra_subprocess = tokio::spawn(async move {
            let output = ghidra_command
                .output()
                .await
                .context("Ghidra could not be executed")?;
            let stdout = String::from_utf8_lossy(&output.stdout);

            if output.status.success() && stdout.contains("Pcode was successfully extracted!") {
                return Ok(());
            }
            if should_print_ghidra_error {
                eprintln!("{stdout}");
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                if let Some(code) = output.status.code() {
                    eprintln!("Ghidra plugin failed with exit code {code}");
                }
            } else {
                eprintln!("Execution of Ghidra plugin failed. Use the --verbose flag to print Ghidra output for troubleshooting.");
            }
            Err(anyhow!("Execution of Ghidra plugin failed."))
        });

        // Wait for the plugin to connect, but bail out if Ghidra exits first.
        tokio::select! {
            res = server.connect() => {
                res.context("Failed to accept client connection")?;
            }
            res = &mut ghidra_subprocess => {
                res.context("The Ghidra task panicked")??;
                return Err(anyhow!("Ghidra exited without connecting to the named pipe"));
            }
        }

        let mut buf = String::new();
        server
            .read_to_string(&mut buf)
            .await
            .context("Error while reading from named pipe")?;
        drop(server);

        debug_settings.print(&buf, debug::Stage::Pcode(debug::PcodeForm::Raw));

        ghidra_subprocess
            .await
            .context("The Ghidra task panicked")??;

        serde_json::from_str(&buf).context("Failed to parse plugin output.")
    })
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
    #[cfg(target_os = "linux")]
    let headless_path = ghidra_path.join("support/analyzeHeadless");
    #[cfg(target_os = "windows")]
    let headless_path = ghidra_path.join("support/analyzeHeadless.bat");
    let tmp_folder = get_tmp_folder()?;
    let filename = file_path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_string_lossy()
        .to_string();
    let ghidra_plugin_path = get_ghidra_plugin_path("p_code_extractor")?;

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
        folder.to_path_buf()
    } else {
        env::temp_dir().join("cwe_checker")
    };
    if !tmp_folder.exists() {
        std::fs::create_dir(&tmp_folder).context("Unable to create temporary folder")?;
    }
    Ok(tmp_folder)
}
