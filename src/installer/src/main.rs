//! This crate automates the installation of cwe_checker.
//! It creates config files, copies the Ghida-Plugin and can search for a Ghidra installation at commonly used locations.

use anyhow::{anyhow, Result};
use clap::Parser;
use directories::{BaseDirs, ProjectDirs, UserDirs};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Parser)]
/// Installs cwe_checker
struct CmdlineArgs {
    /// Path to a ghidra installation.
    ///
    /// If this option is set then the installation will use ghidra at this location.
    ghidra_path: Option<String>,

    #[arg(long, short)]
    /// If true, cwe_checker will be uninstalled.
    uninstall: bool,
}

#[derive(Serialize, Deserialize, Debug)]
/// Structure for ghidra.json file
struct GhidraConfig {
    /// Path to a ghidra installation
    ghidra_path: PathBuf,
}

/// Copies src/config.json to specified location
fn copy_config_json(location: &Path) -> Result<()> {
    let repo_dir = env::current_dir().unwrap();
    std::fs::copy(
        repo_dir.join("src/config.json"),
        location.join("config.json"),
    )?;
    Ok(())
}

/// Returns vector of os-specific locations
fn get_search_locations() -> Vec<PathBuf> {
    let mut locations: Vec<PathBuf> = Vec::new();
    let base_dirs = BaseDirs::new().unwrap();
    let user_dirs = UserDirs::new().unwrap();

    locations.push(base_dirs.data_dir().to_path_buf());
    locations.push(base_dirs.data_local_dir().to_path_buf());
    locations.push(base_dirs.home_dir().to_path_buf());

    if let Some(path) = base_dirs.executable_dir() {
        locations.push(path.to_path_buf());
    }
    if let Some(path) = user_dirs.desktop_dir() {
        locations.push(path.to_path_buf());
    }
    if let Some(path) = user_dirs.download_dir() {
        locations.push(path.to_path_buf());
    }
    if let Some(path) = user_dirs.document_dir() {
        locations.push(path.to_path_buf());
    }
    if let Some(path) = user_dirs.public_dir() {
        locations.push(path.to_path_buf());
    }

    let candidate = Path::new("/opt");
    if candidate.exists() {
        locations.push(candidate.to_path_buf());
    }
    let candidate = Path::new("/usr");
    if candidate.exists() {
        locations.push(candidate.to_path_buf());
    }

    locations
}

/// Returns None if Ghidra were not found. Else returns path to Ghidra, which might be user selected.
fn find_ghidra() -> Result<PathBuf> {
    let mut ghidra_locations: Vec<PathBuf> = get_search_locations()
        .into_iter()
        .flat_map(|x| search_for_ghidrarun(&x))
        .collect();

    ghidra_locations.sort();
    ghidra_locations.dedup_by(|a, b| a == b);

    match ghidra_locations.len() {
        0 => Err(anyhow!("Ghidra not found.")),
        1 => Ok(ghidra_locations.pop().unwrap()),
        _ => select_ghidra_version(ghidra_locations),
    }
}

/// check whether a path starts with ".", indicating a hidden file or folder on Linux.
fn is_hidden(path: &walkdir::DirEntry) -> bool {
    path.file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// Searches for a file containing "ghidraRun" at provided path recursively.
fn search_for_ghidrarun(entry_path: &Path) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    for entry in WalkDir::new(entry_path)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
        .filter_map(|e| e.ok())
        .filter(|e| e.metadata().unwrap().is_file())
    {
        if entry.file_name().to_str().unwrap() == "ghidraRun" {
            let mut hit = entry.into_path();
            hit.pop();
            hits.push(hit);
        }
    }
    hits
}

/// Determines if a path is a ghidra installation
fn is_good_ghidra_location(loc: &Path) -> bool {
    loc.to_path_buf().push("Ghidra/application.properties");
    loc.exists()
}

/// Determines Ghidra versions and provides selection interface for the user.
fn select_ghidra_version(ghidra_locations: Vec<PathBuf>) -> Result<PathBuf> {
    let good_ghidra_locations: Vec<&PathBuf> = ghidra_locations
        .iter()
        .filter(|x| is_good_ghidra_location(x))
        .collect();

    if good_ghidra_locations.is_empty() {
        return Err(anyhow!("Ghidra not found"));
    }

    for (i, loc) in good_ghidra_locations.iter().enumerate() {
        let mut app_prob_file = (*loc).clone();
        app_prob_file.push("Ghidra/application.properties");

        let version = match std::fs::read_to_string(app_prob_file) {
            Ok(app_prop) => app_prop
                .lines()
                .filter_map(|x| x.strip_prefix("application.version="))
                .next()
                .unwrap_or("?")
                .to_string(),

            Err(_) => "?".to_string(),
        };

        println!("Use Ghidra at: {} [v{}]? ({})", loc.display(), version, i);
    }
    println!("Abort ({})", good_ghidra_locations.len());

    get_user_choice(good_ghidra_locations)
}

/// Determines Ghidra versions and provides selection interface for the user.
fn get_user_choice(ghidra_locations: Vec<&PathBuf>) -> Result<PathBuf> {
    println!("Please select (0-{}): ", ghidra_locations.len());

    let mut choice = String::new();

    std::io::stdin().read_line(&mut choice)?;

    match choice.trim().parse::<usize>() {
        Ok(i) if i == ghidra_locations.len() => Err(anyhow!("Installation canceled by user")),
        Ok(i) if i < ghidra_locations.len() => Ok(ghidra_locations[i].clone()),
        Ok(_) => Err(anyhow!("Invalid user input")),
        Err(error) => Err(error.into()),
    }
}

/// Creates ghidra.json for a Ghidra location at provided locaton.
fn create_ghidra_json(location: &Path, ghidra_location: PathBuf) -> Result<()> {
    let conf = GhidraConfig {
        ghidra_path: ghidra_location,
    };
    println!("creating ghidra.json at: {}", location.display());
    std::fs::create_dir_all(location)?;
    std::fs::write(location.join("ghidra.json"), serde_json::to_string(&conf)?)?;
    Ok(())
}

/// Runs Cargo install to install cwe_checker.
fn install_cwe_checker() -> Result<()> {
    match std::process::Command::new("cargo")
        .args(["install", "--path", "src/caller", "--locked"])
        .status()
    {
        Ok(exit_status) if exit_status.success() => Ok(()),
        Ok(_) => Err(anyhow!("Installaton failed")),
        Err(error) => Err(error.into()),
    }
}

/// Recursive copy of files and directories.
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Copy src/ghidra to provided location.
fn copy_ghidra_plugin(target: &Path) -> Result<()> {
    let target = &target;
    let mut source = env::current_dir()?;
    source.push("src/ghidra");

    copy_dir_all(source, target.join("ghidra"))?;
    Ok(())
}

/// Removes provided locations and uninstalls cwe_checker via cargo
fn uninstall(conf_dir: &Path, data_dir: &Path) -> Result<()> {
    if std::fs::remove_dir_all(conf_dir).is_ok() {
        println!("Removing {}", conf_dir.display())
    }
    if std::fs::remove_dir_all(data_dir).is_ok() {
        println!("Removing {}", data_dir.display())
    }
    let _ = std::process::Command::new("cargo")
        .args(["uninstall", "cwe_checker"])
        .status();
    Ok(())
}

fn main() -> Result<()> {
    let cwe_checker_proj_dir = ProjectDirs::from("", "", "cwe_checker").unwrap();
    let cmdline_args = CmdlineArgs::parse();

    match cmdline_args.uninstall {
        true => {
            uninstall(
                cwe_checker_proj_dir.config_dir(),
                cwe_checker_proj_dir.data_dir(),
            )?;
            return Ok(());
        }
        false => match cmdline_args.ghidra_path {
            Some(ghidra_input_location) => create_ghidra_json(
                cwe_checker_proj_dir.config_dir(),
                PathBuf::from(ghidra_input_location),
            )?,
            None if cwe_checker_proj_dir
                .config_dir()
                .join("ghidra.json")
                .exists() =>
            {
                println!(
                    "found ghidra.json at {}, keeping it.",
                    cwe_checker_proj_dir.config_dir().display()
                )
            }
            None => {
                println!("searching for ghidra...");
                match find_ghidra() {
                    Ok(ghidra_location) => {
                        create_ghidra_json(cwe_checker_proj_dir.config_dir(), ghidra_location)?;
                    }
                    Err(err) => return Err(err),
                }
            }
        },
    }

    println!("installing cwe_checker...");
    install_cwe_checker()?;

    println!(
        "creating config.json at: {}",
        cwe_checker_proj_dir.config_dir().display()
    );
    copy_config_json(cwe_checker_proj_dir.config_dir())?;

    println!(
        "copy Ghidra Plugin to: {}",
        cwe_checker_proj_dir.data_dir().display()
    );
    copy_ghidra_plugin(cwe_checker_proj_dir.data_dir())?;
    Ok(())
}
