//! This crate defines the command line interface for the cwe_checker.
//! General documentation about the cwe_checker is contained in the [`cwe_checker_lib`] crate.

extern crate cwe_checker_lib; // Needed for the docstring-link to work

use anyhow::Context;
use anyhow::Error;
use clap::Parser;
use cwe_checker_lib::analysis::graph;
use cwe_checker_lib::pipeline::{disassemble_binary, AnalysisResults};
use cwe_checker_lib::utils::binary::BareMetalConfig;
use cwe_checker_lib::utils::log::{print_all_messages, LogLevel};
use cwe_checker_lib::utils::read_config_file;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
/// Find vulnerable patterns in binary executables
struct CmdlineArgs {
    /// The path to the binary.
    #[arg(required_unless_present("module_versions"), value_parser = check_file_existence)]
    binary: Option<String>,

    /// Path to a custom configuration file to use instead of the standard one.
    #[arg(long, short, value_parser = check_file_existence)]
    config: Option<String>,

    /// Write the results to a file instead of stdout.
    /// This only affects CWE warnings. Log messages are still printed to stdout.
    #[arg(long, short)]
    out: Option<String>,

    /// Specify a specific set of checks to be run as a comma separated list, e.g. 'CWE332,CWE476,CWE782'.
    ///
    /// Use the "--module-versions" command line option to get a list of all valid check names.
    #[arg(long, short)]
    partial: Option<String>,

    /// Generate JSON output.
    #[arg(long, short)]
    json: bool,

    /// Do not print log messages. This prevents polluting stdout for json output.
    #[arg(long, short)]
    quiet: bool,

    /// Print additional debug log messages.
    #[arg(long, short, conflicts_with("quiet"))]
    verbose: bool,

    /// Include various statistics in the log messages.
    /// This can be helpful for assessing the analysis quality for the input binary.
    #[arg(long, conflicts_with("quiet"))]
    statistics: bool,

    /// Path to a configuration file for analysis of bare metal binaries.
    ///
    /// If this option is set then the input binary is treated as a bare metal binary regardless of its format.
    #[arg(long, value_parser = check_file_existence)]
    bare_metal_config: Option<String>,

    /// Prints out the version numbers of all known modules.
    #[arg(long)]
    module_versions: bool,

    /// Output for debugging purposes.
    /// The current behavior of this flag is unstable and subject to change.
    #[arg(long, hide(true))]
    debug: bool,
}

fn main() -> Result<(), Error> {
    let cmdline_args = CmdlineArgs::parse();

    run_with_ghidra(&cmdline_args)
}

/// Return `Ok(file_path)` only if `file_path` points to an existing file.
fn check_file_existence(file_path: &str) -> Result<String, String> {
    if std::fs::metadata(file_path)
        .map_err(|err| format!("{err}"))?
        .is_file()
    {
        Ok(file_path.to_string())
    } else {
        Err(format!("{file_path} is not a file."))
    }
}

/// Run the cwe_checker with Ghidra as its backend.
fn run_with_ghidra(args: &CmdlineArgs) -> Result<(), Error> {
    let mut modules = cwe_checker_lib::get_modules();
    if args.module_versions {
        // Only print the module versions and then quit.
        println!("[cwe_checker] module_versions:");
        for module in modules.iter() {
            println!("{module}");
        }
        return Ok(());
    }

    // Get the configuration file
    let config: serde_json::Value = if let Some(ref config_path) = args.config {
        let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
        serde_json::from_reader(file).context("Parsing of the configuration file failed")?
    } else {
        read_config_file("config.json")?
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
        modules.retain(|module| module.name != "CWE78");
    }
    let binary_file_path = PathBuf::from(args.binary.clone().unwrap());

    let (binary, project, mut all_logs) =
        disassemble_binary(&binary_file_path, bare_metal_config_opt, args.verbose)?;

    // Generate the control flow graph of the program
    let (control_flow_graph, mut logs_graph) = graph::get_program_cfg_with_logs(&project.program);
    all_logs.append(&mut logs_graph);

    let analysis_results = AnalysisResults::new(&binary, &control_flow_graph, &project);

    let modules_depending_on_string_abstraction = BTreeSet::from_iter(["CWE78"]);
    let modules_depending_on_pointer_inference = BTreeSet::from_iter([
        "CWE119", "CWE134", "CWE416", "CWE457", "CWE476", "Memory", "CWE190", "CWE789",
    ]);

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
        return Ok(());
    }

    // Execute the modules and collect their logs and CWE-warnings.
    let mut all_cwes = Vec::new();
    for module in modules {
        let (mut logs, mut cwes) = (module.run)(&analysis_results, &config[&module.name]);
        all_logs.append(&mut logs);
        all_cwes.append(&mut cwes);
    }
    all_cwes.sort();

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
    Ok(())
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
                panic!("Error: {module_name} is not a valid module name.")
            }
        })
        .collect();
}
