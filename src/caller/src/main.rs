//! This crate defines the command line interface for the cwe_checker.
//! General documentation about the cwe_checker is contained in the [`cwe_checker_lib`] crate.

extern crate cwe_checker_lib; // Needed for the docstring-link to work

use cwe_checker_lib::analysis::graph;
use cwe_checker_lib::utils::binary::{BareMetalConfig, RuntimeMemoryImage};
use cwe_checker_lib::utils::log::{print_all_messages, LogLevel};
use cwe_checker_lib::utils::{get_ghidra_plugin_path, read_config_file};
use cwe_checker_lib::AnalysisResults;
use cwe_checker_lib::{intermediate_representation::Project, utils::log::LogMessage};
use nix::{sys::stat, unistd};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
/// Find vulnerable patterns in binary executables
struct CmdlineArgs {
    /// The path to the binary.
    #[structopt(required_unless("module-versions"), validator(check_file_existence))]
    binary: Option<String>,

    /// Path to a custom configuration file to use instead of the standard one.
    #[structopt(long, short, validator(check_file_existence))]
    config: Option<String>,

    /// Write the results to a file instead of stdout.
    /// This only affects CWE warnings. Log messages are still printed to stdout.
    #[structopt(long, short)]
    out: Option<String>,

    /// Specify a specific set of checks to be run as a comma separated list, e.g. 'CWE332,CWE476,CWE782'.
    ///
    /// Use the "--module-versions" command line option to get a list of all valid check names.
    #[structopt(long, short)]
    partial: Option<String>,

    /// Generate JSON output.
    #[structopt(long, short)]
    json: bool,

    /// Do not print log messages. This prevents polluting stdout for json output.
    #[structopt(long, short)]
    quiet: bool,

    /// Print additional debug log messages.
    #[structopt(long, short, conflicts_with("quiet"))]
    verbose: bool,

    /// Include various statistics in the log messages.
    /// This can be helpful for assessing the analysis quality for the input binary.
    #[structopt(long, conflicts_with("quiet"))]
    statistics: bool,

    /// Path to a configuration file for analysis of bare metal binaries.
    ///
    /// If this option is set then the input binary is treated as a bare metal binary regardless of its format.
    #[structopt(long)]
    bare_metal_config: Option<String>,

    /// Prints out the version numbers of all known modules.
    #[structopt(long)]
    module_versions: bool,

    /// Output for debugging purposes.
    /// The current behavior of this flag is unstable and subject to change.
    #[structopt(long, hidden = true)]
    debug: bool,
}

fn main() {
    let cmdline_args = CmdlineArgs::from_args();

    run_with_ghidra(&cmdline_args);
}

/// Check the existence of a file
fn check_file_existence(file_path: String) -> Result<(), String> {
    if std::fs::metadata(&file_path)
        .map_err(|err| format!("{}", err))?
        .is_file()
    {
        Ok(())
    } else {
        Err(format!("{} is not a file.", file_path))
    }
}

/// Run the cwe_checker with Ghidra as its backend.
fn run_with_ghidra(args: &CmdlineArgs) {
    let mut modules = cwe_checker_lib::get_modules();
    if args.module_versions {
        // Only print the module versions and then quit.
        println!("[cwe_checker] module_versions:");
        for module in modules.iter() {
            println!("{}", module);
        }
        return;
    }

    // Get the configuration file
    let config: serde_json::Value = if let Some(ref config_path) = args.config {
        let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
        serde_json::from_reader(file).expect("Parsing of the configuration file failed")
    } else {
        read_config_file("config.json")
    };

    // Get the bare metal configuration file if it is provided
    let bare_metal_config_opt: Option<BareMetalConfig> =
        args.bare_metal_config.as_ref().map(|config_path| {
            let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
            serde_json::from_reader(file)
                .expect("Parsing of the bare metal configuration file failed")
        });

    // Filter the modules to be executed if the `--partial` parameter is set.
    if let Some(ref partial_module_list) = args.partial {
        filter_modules_for_partial_run(&mut modules, partial_module_list);
    } else {
        // TODO: CWE78 is disabled on a standard run for now,
        // because it uses up huge amounts of RAM and computation time on some binaries.
        modules = modules
            .into_iter()
            .filter(|module| module.name != "CWE78")
            .collect();
    }

    let binary_file_path = PathBuf::from(args.binary.clone().unwrap());
    let binary: Vec<u8> = std::fs::read(&binary_file_path).unwrap_or_else(|_| {
        panic!(
            "Error: Could not read from file path {}",
            binary_file_path.display()
        )
    });
    let (mut project, mut all_logs) = get_project_from_ghidra(
        &binary_file_path,
        &binary[..],
        bare_metal_config_opt.clone(),
    );
    // Normalize the project and gather log messages generated from it.
    all_logs.append(&mut project.normalize());

    // Generate the representation of the runtime memory image of the binary
    let mut runtime_memory_image = if let Some(bare_metal_config) = bare_metal_config_opt.as_ref() {
        RuntimeMemoryImage::new_from_bare_metal(&binary, bare_metal_config).unwrap_or_else(|err| {
            panic!("Error while generating runtime memory image: {}", err);
        })
    } else {
        RuntimeMemoryImage::new(&binary).unwrap_or_else(|err| {
            panic!("Error while generating runtime memory image: {}", err);
        })
    };
    if project.program.term.address_base_offset != 0 {
        // We adjust the memory addresses once globally
        // so that other analyses do not have to adjust their addresses.
        runtime_memory_image.add_global_memory_offset(project.program.term.address_base_offset);
    }
    // Generate the control flow graph of the program
    let extern_sub_tids = project
        .program
        .term
        .extern_symbols
        .keys()
        .cloned()
        .collect();
    let control_flow_graph = graph::get_program_cfg(&project.program, extern_sub_tids);

    let analysis_results = AnalysisResults::new(
        &binary,
        &runtime_memory_image,
        &control_flow_graph,
        &project,
    );

    let modules_depending_on_string_abstraction = BTreeSet::from_iter(["CWE78"]);
    let modules_depending_on_pointer_inference =
        BTreeSet::from_iter(["CWE119", "CWE134", "CWE476", "Memory"]);

    let string_abstraction_needed = modules
        .iter()
        .any(|module| modules_depending_on_string_abstraction.contains(&module.name));

    let pi_analysis_needed = string_abstraction_needed
        || modules
            .iter()
            .any(|module| modules_depending_on_pointer_inference.contains(&module.name));

    // Compute function signatures if required
    let function_signatures = if pi_analysis_needed {
        let (function_signatures, mut logs) = analysis_results.compute_function_signatures();
        all_logs.append(&mut logs);
        Some(function_signatures)
    } else {
        None
    };
    let analysis_results = analysis_results.with_function_signatures(function_signatures.as_ref());
    // Compute pointer inference if required
    let pi_analysis_results = if pi_analysis_needed {
        Some(analysis_results.compute_pointer_inference(&config["Memory"], args.statistics))
    } else {
        None
    };
    let analysis_results = analysis_results.with_pointer_inference(pi_analysis_results.as_ref());
    // Compute string abstraction analysis if required
    let string_abstraction_results =
        if string_abstraction_needed {
            Some(analysis_results.compute_string_abstraction(
                &config["StringAbstraction"],
                pi_analysis_results.as_ref(),
            ))
        } else {
            None
        };
    let analysis_results =
        analysis_results.with_string_abstraction(string_abstraction_results.as_ref());

    // Print debug and then return.
    // Right now there is only one debug printing function.
    // When more debug printing modes exist, this behaviour will change!
    if args.debug {
        cwe_checker_lib::analysis::pointer_inference::run(
            &analysis_results,
            serde_json::from_value(config["Memory"].clone()).unwrap(),
            true,
            false,
        );
        return;
    }

    // Execute the modules and collect their logs and CWE-warnings.
    let mut all_cwes = Vec::new();
    for module in modules {
        let (mut logs, mut cwes) = (module.run)(&analysis_results, &config[&module.name]);
        all_logs.append(&mut logs);
        all_cwes.append(&mut cwes);
    }

    // Print the results of the modules.
    if args.quiet {
        all_logs = Vec::new(); // Suppress all log messages since the `--quiet` flag is set.
    } else {
        if args.statistics {
            cwe_checker_lib::utils::log::add_debug_log_statistics(&mut all_logs);
        }
        if !args.verbose {
            all_logs.retain(|log_msg| log_msg.level != LogLevel::Debug);
        }
    }
    print_all_messages(all_logs, all_cwes, args.out.as_deref(), args.json);
}

/// Only keep the modules specified by the `--partial` parameter in the `modules` list.
/// The parameter is a comma-separated list of module names, e.g. 'CWE332,CWE476,CWE782'.
fn filter_modules_for_partial_run(
    modules: &mut Vec<&cwe_checker_lib::CweModule>,
    partial_param: &str,
) {
    let module_names: HashSet<&str> = partial_param.split(',').collect();
    *modules = module_names
        .into_iter()
        .filter_map(|module_name| {
            if let Some(module) = modules.iter().find(|module| module.name == module_name) {
                Some(*module)
            } else if module_name.is_empty() {
                None
            } else {
                panic!("Error: {} is not a valid module name.", module_name)
            }
        })
        .collect();
}

/// Execute the `p_code_extractor` plugin in ghidra and parse its output into the `Project` data structure.
fn get_project_from_ghidra(
    file_path: &Path,
    binary: &[u8],
    bare_metal_config_opt: Option<BareMetalConfig>,
) -> (Project, Vec<LogMessage>) {
    let bare_metal_base_address_opt = bare_metal_config_opt
        .as_ref()
        .map(|config| config.parse_binary_base_address());
    let ghidra_path: std::path::PathBuf =
        serde_json::from_value(read_config_file("ghidra.json")["ghidra_path"].clone())
            .expect("Path to Ghidra not configured.");
    let headless_path = ghidra_path.join("support/analyzeHeadless");

    // Find the correct paths for temporary files.
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")
        .expect("Could not determine path for temporary files");
    let tmp_folder = if let Some(folder) = project_dirs.runtime_dir() {
        folder
    } else {
        Path::new("/tmp/cwe_checker")
    };
    if !tmp_folder.exists() {
        std::fs::create_dir(tmp_folder).expect("Unable to create temporary folder");
    }
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
    let filename = file_path
        .file_name()
        .expect("Invalid file name")
        .to_string_lossy()
        .to_string();
    let ghidra_plugin_path = get_ghidra_plugin_path("p_code_extractor");

    // Create a unique name for the pipe
    let fifo_path = tmp_folder.join(format!("pcode_{}.pipe", timestamp_suffix));

    // Create a new fifo and give read and write rights to the owner
    if let Err(err) = unistd::mkfifo(&fifo_path, stat::Mode::from_bits(0o600).unwrap()) {
        eprintln!("Error creating FIFO pipe: {}", err);
        std::process::exit(101);
    }

    let thread_fifo_path = fifo_path.clone();
    let thread_file_path = file_path.to_path_buf();
    let thread_tmp_folder = tmp_folder.to_path_buf();
    // Execute Ghidra in a new thread and return a Join Handle, so that the thread is only joined
    // after the output has been read into the cwe_checker
    let ghidra_subprocess = thread::spawn(move || {
        let mut ghidra_command = Command::new(&headless_path);
        ghidra_command
            .arg(&thread_tmp_folder) // The folder where temporary files should be stored
            .arg(format!("PcodeExtractor_{}_{}", filename, timestamp_suffix)) // The name of the temporary Ghidra Project.
            .arg("-import") // Import a file into the Ghidra project
            .arg(thread_file_path) // File import path
            .arg("-postScript") // Execute a script after standard analysis by Ghidra finished
            .arg(ghidra_plugin_path.join("PcodeExtractor.java")) // Path to the PcodeExtractor.java
            .arg(thread_fifo_path) // The path to the named pipe (fifo)
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
                .arg(bare_metal_config.processor_id);
        }
        let output = match ghidra_command.output() // Execute the command and catch its output.
        {
            Ok(output) => output,
            Err(err) => {
                eprintln!("Error: Ghidra could not be executed:\n{}", err);
                std::process::exit(101);
            }
        };

        match String::from_utf8(output.stdout.clone()) {
            Ok(standard_out) => {
                if !standard_out.contains("Pcode was successfully extracted!") {
                    eprintln!("Execution of Ghidra plugin failed: Process was terminated.");
                    let error_message: String =
                        standard_out.lines().rev().collect::<Vec<&str>>()[..2].join("\n");
                    eprintln!("{}", error_message);
                    std::process::exit(101);
                }
            }
            Err(_) => {
                eprintln!("Execution of Ghidra plugin failed: Process was terminated.");
                std::process::exit(101);
            }
        }

        if !output.status.success() {
            match output.status.code() {
                Some(code) => {
                    eprintln!("{}", String::from_utf8(output.stdout).unwrap());
                    eprintln!("{}", String::from_utf8(output.stderr).unwrap());
                    eprintln!("Execution of Ghidra plugin failed with exit code {}", code);
                    std::process::exit(101);
                }
                None => {
                    eprintln!("Execution of Ghidra plugin failed: Process was terminated.");
                    std::process::exit(101);
                }
            }
        }
    });

    // Open the FIFO
    let file = std::fs::File::open(fifo_path.clone()).expect("Could not open FIFO.");

    let mut project_pcode: cwe_checker_lib::pcode::Project =
        serde_json::from_reader(std::io::BufReader::new(file)).unwrap();
    let mut log_messages = project_pcode.normalize();
    let project: Project = match cwe_checker_lib::utils::get_binary_base_address(binary) {
        Ok(binary_base_address) => project_pcode.into_ir_project(binary_base_address),
        Err(_err) => {
            if let Some(binary_base_address) = bare_metal_base_address_opt {
                let mut project = project_pcode.into_ir_project(binary_base_address);
                project.program.term.address_base_offset = 0;
                project
            } else {
                log_messages.push(LogMessage::new_info("Could not determine binary base address. Using base address of Ghidra output as fallback."));
                let mut project = project_pcode.into_ir_project(0);
                // For PE files setting the address_base_offset to zero is a hack, which worked for the tested PE files.
                // But this hack will probably not work in general!
                project.program.term.address_base_offset = 0;
                project
            }
        }
    };

    ghidra_subprocess
        .join()
        .expect("The Ghidra thread to be joined has panicked!");

    std::fs::remove_file(fifo_path).unwrap();

    (project, log_messages)
}
