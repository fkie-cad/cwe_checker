//! This crate defines automates the installation of cwe_checker.
//! It creates config files, copies the Ghida-Plugin and can search for a Ghidra installation at common used locations.

use directories::{BaseDirs, ProjectDirs, UserDirs};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::{fs, io};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Debug)]
struct GhidraConfig {
    ghidra_path: PathBuf,
}

/// Copies src/config.json to specified location
fn copy_config_json(location: &Path) {
    let repo_dir = env::current_dir().unwrap();
    std::fs::copy(
        &repo_dir.join("src/config.json"),
        location.join("config.json"),
    )
    .unwrap_or_else(|_| panic!("Copy to {} failed", location.display()));
}

/// Returns vector of os-specific locations
fn get_search_locations() -> Vec<PathBuf> {
    let mut locations: Vec<PathBuf> = Vec::new();
    let base_dirs = BaseDirs::new().expect("Could not derive BaseDirs");
    let user_dirs = UserDirs::new().expect("Could not derive UserDirs");

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
fn find_ghidra() -> Option<PathBuf> {
    let mut ghidra_locations: Vec<PathBuf> = get_search_locations()
        .into_iter()
        .filter_map(|x| search_for_ghidrarun(&x))
        .collect();

    match ghidra_locations.len() {
        0 => None,
        1 => Some(ghidra_locations.pop().unwrap()),
        _ => select_ghidra_version(ghidra_locations),
    }
}

/// Searches for a file containing "ghidraRun" at provided path recursively.
fn search_for_ghidrarun(entry_path: &Path) -> Option<PathBuf> {
    for entry in WalkDir::new(entry_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.metadata().unwrap().is_file())
    {
        if entry.file_name().to_str().unwrap().contains("ghidraRun") {
            let mut hit = entry.into_path();
            hit.pop();
            return Some(hit);
        }
    }
    None
}

/// Determines Ghidra versions and provides selection interface for the user.
fn select_ghidra_version(mut ghidra_locations: Vec<PathBuf>) -> Option<PathBuf> {
    let mut i = 0;
    while i < ghidra_locations.len() {
        ghidra_locations[i].push("Ghidra/application.properties");
        let app_prop = std::fs::read_to_string(&ghidra_locations[i]);

        match app_prop {
            Ok(properties) => {
                let version: &str = properties
                    .lines()
                    .filter_map(|x| x.strip_prefix("application.version="))
                    .next()
                    .unwrap_or_else(|| panic!("error parsing {}", ghidra_locations[i].display()));
                ghidra_locations[i].pop();
                ghidra_locations[i].pop();
                println!(
                    "Use Ghidra at: {} [v{}]? ({})",
                    ghidra_locations[i].display(),
                    version,
                    i
                );
                i += 1;
            }

            Err(_) => {
                ghidra_locations.remove(i);
            }
        }
    }
    if ghidra_locations.is_empty() {
        return None;
    }

    get_user_choice(&ghidra_locations)
}

/// Determines Ghidra versions and provides selection interface for the user.
fn get_user_choice(ghidra_locations: &[PathBuf]) -> Option<PathBuf> {
    println!("Please select (0-{}): ", ghidra_locations.len() - 1);

    let mut choice = String::new();

    std::io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read line");

    match choice.trim().parse::<usize>() {
        Ok(i) => {
            if i < ghidra_locations.len() {
                Some(ghidra_locations[i].clone())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Creates ghidra.json for a Ghidra location at provided locaton.
fn create_ghidra_json(location: &Path, ghidra_location: Option<PathBuf>) {
    match ghidra_location {
        Some(loc) => {
            let conf = GhidraConfig { ghidra_path: loc };
            println!("{:?}", conf);
            std::fs::write(
                location.join("ghidra.json"),
                serde_json::to_string(&conf).unwrap(),
            )
            .unwrap()
        }
        None => panic!("Error: Could not find Ghidra."),
    }
}

/// Runs Cargo install to install cwe_checker.
fn install_cwe_checker() {
    std::process::Command::new("cargo")
        .args(["install", "--path", "src/caller", "--locked"])
        .status()
        .expect("Failed to install cwe-checker");
}

// Recursive copy of files and directories.
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
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

// Copy src/ghidra to provided location.
fn copy_ghidra_plugin(target: &Path) {
    let target = &target;
    let mut source = env::current_dir().unwrap();
    source.push("src/ghidra");

    copy_dir_all(source, target.join("ghidra")).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cwe_checker_conf_dir = ProjectDirs::from("", "", "cwe_checker").unwrap();
    std::fs::create_dir_all(cwe_checker_conf_dir.config_dir()).unwrap_or_else(|_| {
        panic!(
            "Could not create {}",
            cwe_checker_conf_dir.config_dir().display()
        )
    });

    println!("creating config.json...");
    copy_config_json(cwe_checker_conf_dir.config_dir());

    println!("create ghidra.json...");
    if args.len() == 2 {
        create_ghidra_json(
            cwe_checker_conf_dir.config_dir(),
            Some(PathBuf::from(&args[1])),
        );
    } else if cwe_checker_conf_dir
        .config_dir()
        .join("ghidra.json")
        .exists()
    {
        println!(
            "found ghidra.json at {}, keeping it.",
            cwe_checker_conf_dir.config_dir().display()
        );
    } else {
        println!("searching for ghidra...");
        let ghidra_location = find_ghidra();

        create_ghidra_json(cwe_checker_conf_dir.config_dir(), ghidra_location);
    }

    println!("installing CWE-Checker...");
    install_cwe_checker();

    println!("copy Ghidra Plugin...");
    copy_ghidra_plugin(cwe_checker_conf_dir.data_dir())
}
