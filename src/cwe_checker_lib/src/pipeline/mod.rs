//! This module contains functions and structs helpful for building a complete analysis pipeline
//! starting from the binary file path.

mod results;
pub use results::AnalysisResults;

use crate::intermediate_representation::{Project, RuntimeMemoryImage};
use crate::prelude::*;
use crate::utils::log::LogMessage;
use crate::utils::{binary::BareMetalConfig, ghidra::get_project_from_ghidra};
use std::path::Path;

/// Disassemble the given binary and parse it to a [`Project`](crate::intermediate_representation::Project) struct.
///
/// If successful, returns the binary file (as a byte vector), the parsed project struct,
/// and a vector of log messages generated during the process.
pub fn disassemble_binary(
    binary_file_path: &Path,
    bare_metal_config_opt: Option<BareMetalConfig>,
    verbose_flag: bool,
) -> Result<(Vec<u8>, Project, Vec<LogMessage>), Error> {
    let binary: Vec<u8> =
        std::fs::read(binary_file_path).context("Could not read from binary file path {}")?;
    let (mut project, mut all_logs) = get_project_from_ghidra(
        binary_file_path,
        &binary[..],
        bare_metal_config_opt.clone(),
        verbose_flag,
    )?;
    // Normalize the project and gather log messages generated from it.
    all_logs.append(&mut project.normalize());

    // Generate the representation of the runtime memory image of the binary
    let mut runtime_memory_image = if let Some(bare_metal_config) = bare_metal_config_opt.as_ref() {
        RuntimeMemoryImage::new_from_bare_metal(&binary, bare_metal_config)
            .context("Error while generating runtime memory image.")?
    } else {
        RuntimeMemoryImage::new(&binary).context("Error while generating runtime memory image.")?
    };
    if project.program.term.address_base_offset != 0 {
        // We adjust the memory addresses once globally
        // so that other analyses do not have to adjust their addresses.
        runtime_memory_image.add_global_memory_offset(project.program.term.address_base_offset);
    }
    project.runtime_memory_image = runtime_memory_image;

    Ok((binary, project, all_logs))
}
