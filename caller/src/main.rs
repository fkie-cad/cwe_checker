use std::process::Command;
use structopt::StructOpt;

// TODO: Add validation function for `--partial=???` parameter.
// TODO: Add module version printing function

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

    /// Specify a specific set of checks to be run.
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
}

fn main() {
    let cmdline_args = CmdlineArgs::from_args();

    if cmdline_args.module_versions {
        println!("printing module versions");
        todo!();
        return;
    } else if let Some(exit_code) = build_bap_command(&cmdline_args).status().unwrap().code() {
        std::process::exit(exit_code);
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
