use cwe_checker_rs::intermediate_representation::Project;
use cwe_checker_rs::utils::log::print_all_messages;
use cwe_checker_rs::utils::{get_ghidra_plugin_path, read_config_file};
use cwe_checker_rs::AnalysisResults;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
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

    /// Write the results to a file.
    #[structopt(long, short)]
    out: Option<String>,

    /// Specify a specific set of checks to be run as a comma separated list, e.g. 'CWE332,CWE476,CWE782'.
    #[structopt(long, short)]
    partial: Option<String>,

    /// Generate JSON output.
    #[structopt(long, short)]
    json: bool,

    /// Do not print log messages. This prevents polluting STDOUT for json output.
    #[structopt(long, short)]
    quiet: bool,

    /// Checks if there is a path from an input function to a CWE hit.
    #[structopt(long)]
    check_path: bool,

    /// Prints out the version numbers of all known modules.
    #[structopt(long)]
    module_versions: bool,

    /// Output for debugging purposes.
    /// The current behavior of this flag is unstable and subject to change.
    #[structopt(long, hidden = true)]
    debug: bool,

    /// Use BAP as backend (instead of Ghidra). Requires BAP and the cwe_checker-BAP-plugin to be installed.
    #[structopt(long, hidden = true)]
    bap: bool,
}

fn main() {
    let cmdline_args = CmdlineArgs::from_args();

    if cmdline_args.bap {
        // Use BAP as backend
        if let Some(exit_code) = build_bap_command(&cmdline_args).status().unwrap().code() {
            std::process::exit(exit_code);
        }
    } else {
        // Use Ghidra as backend
        run_with_ghidra(cmdline_args);
    }
}

/// Build the BAP command corresponding to the given command line arguments.
fn build_bap_command(args: &CmdlineArgs) -> Command {
    let mut command = Command::new("bap");
    command.arg(args.binary.as_ref().unwrap());
    command.arg("--pass=cwe-checker");
    if let Some(ref string) = args.config {
        command.arg("--cwe-checker-config=".to_string() + string);
    }
    if let Some(ref string) = args.out {
        command.arg("--cwe-checker-out=".to_string() + string);
    }
    if let Some(ref string) = args.partial {
        command.arg("--cwe-checker-partial=".to_string() + string);
    }
    if args.json {
        command.arg("--cwe-checker-json");
    }
    if args.quiet {
        command.arg("--cwe-checker-no-logging");
    }
    if args.check_path {
        command.arg("--cwe-checker-check-path");
    }
    if args.module_versions {
        command.arg("--cwe-checker-module-versions");
    }
    command
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
fn run_with_ghidra(args: CmdlineArgs) {
    let mut modules = cwe_checker_rs::get_modules();
    if args.module_versions {
        // Only print the module versions and then quit.
        println!("[cwe_checker] module_versions:");
        for module in modules.iter() {
            println!("{}", module);
        }
        return;
    }

    if args.check_path {
        panic!("Check-path module not yet implemented for the Ghidra backend");
    }

    // Get the configuration file
    let config: serde_json::Value = if let Some(config_path) = args.config {
        let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
        serde_json::from_reader(file).expect("Parsing of the configuration file failed")
    } else {
        read_config_file("config.json")
    };

    // Filter the modules to be executed if the `--partial` parameter is set.
    if let Some(ref partial_module_list) = args.partial {
        filter_modules_for_partial_run(&mut modules, partial_module_list);
    }

    let binary_file_path = PathBuf::from(args.binary.unwrap());
    let binary: Vec<u8> = std::fs::read(&binary_file_path).unwrap_or_else(|_| {
        panic!(
            "Error: Could not read from file path {}",
            binary_file_path.display()
        )
    });
    let mut project = get_project_from_ghidra(&binary_file_path);
    // Normalize the project and gather log messages generated from it.
    let mut all_logs = project.normalize();
    let mut analysis_results = AnalysisResults::new(&binary, &project);

    let pointer_inference_results = if modules
        .iter()
        .any(|module| module.name == "CWE476" || module.name == "Memory" || module.name == "CWE367")
    {
        Some(analysis_results.compute_pointer_inference(&config["Memory"]))
    } else {
        None
    };
    analysis_results = analysis_results.set_pointer_inference(pointer_inference_results.as_ref());

    // Print debug and then return.
    // Right now there is only one debug printing function.
    // When more debug printing modes exist, this behaviour will change!
    if args.debug {
        cwe_checker_rs::analysis::pointer_inference::run(
            &project,
            serde_json::from_value(config["Memory"].clone()).unwrap(),
            true,
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
    }
    print_all_messages(all_logs, all_cwes, args.out.as_deref(), args.json);
}

/// Only keep the modules specified by the `--partial` parameter in the `modules` list.
/// The parameter is a comma-separated list of module names, e.g. 'CWE332,CWE476,CWE782'.
fn filter_modules_for_partial_run(
    modules: &mut Vec<&cwe_checker_rs::CweModule>,
    partial_param: &str,
) {
    let module_names: HashSet<&str> = partial_param.split(',').collect();
    *modules = module_names
        .into_iter()
        .filter_map(|module_name| {
            if let Some(module) = modules.iter().find(|module| module.name == module_name) {
                Some(*module)
            } else if module_name == "" {
                None
            } else {
                panic!("Error: {} is not a valid module name.", module_name)
            }
        })
        .collect();
}

/// Execute the `p_code_extractor` plugin in ghidra and parse its output into the `Project` data structure.
fn get_project_from_ghidra(file_path: &Path) -> Project {
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
        .to_string_lossy();
    let output_filename = format!("{}_{}.json", filename, timestamp_suffix);
    let output_path = tmp_folder.join(output_filename);
    let ghidra_plugin_path = get_ghidra_plugin_path("p_code_extractor");
    // Execute Ghidra
    let output = Command::new(&headless_path)
        .arg(&tmp_folder) // The folder where temporary files should be stored
        .arg(format!("PcodeExtractor_{}_{}", filename, timestamp_suffix)) // The name of the temporary Ghidra Project.
        .arg("-import") // Import a file into the Ghidra project
        .arg(file_path) // File import path
        .arg("-postScript") // Execute a script after standard analysis by Ghidra finished
        .arg(ghidra_plugin_path.join("PcodeExtractor.java")) // Path to the PcodeExtractor.java
        .arg(&output_path) // Output file path
        .arg("-scriptPath") // Add a folder containing additional script files to the Ghidra script file search paths
        .arg(ghidra_plugin_path) // Path to the folder containing the PcodeExtractor.java (so that the other java files can be found.)
        .arg("-deleteProject") // Delete the temporary project after the script finished
        .arg("-analysisTimeoutPerFile") // Set a timeout for how long the standard analysis can run before getting aborted
        .arg("3600") // Timeout of one hour (=3600 seconds) // TODO: The post-script can detect that the timeout fired and react accordingly.
        .output() // Execute the command and catch its output.
        .unwrap();
    if !output.status.success() {
        match output.status.code() {
            Some(code) => {
                println!("{}", String::from_utf8(output.stdout).unwrap());
                println!("{}", String::from_utf8(output.stderr).unwrap());
                panic!("Execution of Ghidra plugin failed with exit code {}", code)
            }
            None => panic!("Execution of Ghidra plugin failed: Process was terminated."),
        }
    }
    // Read the results from the Ghidra script
    let file =
        std::fs::File::open(&output_path).expect("Could not read results of the Ghidra script");
    let mut project_pcode: cwe_checker_rs::pcode::Project =
        serde_json::from_reader(std::io::BufReader::new(file)).unwrap();
    project_pcode.normalize();
    let project: Project = project_pcode.into();
    // delete the temporary file again.
    std::fs::remove_file(output_path).unwrap();
    project
}
