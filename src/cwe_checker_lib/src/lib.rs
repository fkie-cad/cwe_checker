/*!
The main library of the cwe_checker containing all CWE checks and analysis modules.

# What is the cwe_checker

The cwe_checker is a tool for finding common bug classes on binaries using static analysis.
These bug classes are formally known as [Common Weakness Enumerations](https://cwe.mitre.org/) (CWEs).
Its main goal is to aid analysts to quickly find vulnerable code paths.

Currently its main focus are ELF binaries that are commonly found on Linux and Unix operating systems.
The cwe_checker uses [Ghidra](https://ghidra-sre.org/) to disassemble binaries into one common intermediate representation
and implements its own analyses on this IR.
Hence, the analyses can be run on all CPU architectures that Ghidra can disassemble,
which makes the *cwe_checker* a valuable tool for firmware analysis.

# Usage

If the cwe_checker is installed locally, just run
```sh
cwe_checker BINARY
```
If you want to use the official docker image, you have to mount the input binary into the docker container, e.g.
```sh
docker run --rm -v $(pwd)/BINARY:/input fkiecad/cwe_checker /input
```
One can modify the behaviour of the cwe_checker through the command line.
Use the `--help` command line option for more information.
One can also provide a custom configuration file to modify the behaviour of each check
through the `--config` command line option.
Start by taking a look at the standard configuration file located at `src/config.json`
and read the [check-specific documentation](crate::checkers) for more details about each field in the configuration file.

## For bare-metal binaries

The cwe_checker offers experimental support for analyzing bare-metal binaries.
For that one needs to provide a bare metal configuration file via the `--bare-metal-config` command line option.
An example for such a configuration file can be found at `bare_metal/stm32f407vg.json`
(which was created and tested for an STM32F407VG MCU).

For more information on the necessary fields of the configuration file
and the assumed memory model when analyzing bare metal binaries
see the [configuration struct documentation](crate::utils::binary::BareMetalConfig).

# Integration into other tools

### Integration into Ghidra

To import the results of the cwe_checker as bookmarks and end-of-line comments into Ghidra,
one can use the Ghidra script located at `ghidra_plugin/cwe_checker_ghidra_plugin.py`.
Detailed usage instructions are contained in the file.

### Integration into FACT

[FACT](https://github.com/fkie-cad/FACT_core) already contains a ready-to-use cwe_checker plugin,
which lets you run the cwe_checker and view its result through the FACT user interface.

# Further documentation

You can find out more information about each check, including known false positives and false negatives,
by reading the check-specific module documentation in the [`checkers`] module.
*/

use std::collections::BTreeMap;

pub mod abstract_domain;
pub mod analysis;
pub mod checkers;
pub mod intermediate_representation;
pub mod pcode;
pub mod utils;

use abstract_domain::BricksDomain;
use analysis::function_signature::FunctionSignature;
use analysis::graph::Graph;
use analysis::pointer_inference::PointerInference;
use analysis::string_abstraction::StringAbstraction;
use intermediate_representation::Project;
use utils::binary::RuntimeMemoryImage;
use utils::log::{CweWarning, LogMessage};

mod prelude {
    pub use apint::Width;
    pub use serde::{Deserialize, Serialize};

    pub use crate::intermediate_representation::{Bitvector, BitvectorExtended, ByteSize};
    pub use crate::intermediate_representation::{Term, Tid};
    pub use crate::AnalysisResults;
    pub use anyhow::{anyhow, Error};
}
use prelude::*;

/// The generic function signature for the main function of a CWE module
pub type CweModuleFn =
    fn(&AnalysisResults, &serde_json::Value) -> (Vec<LogMessage>, Vec<CweWarning>);

/// A structure containing general information about a CWE analysis module,
/// including the function to be called to run the analysis.
pub struct CweModule {
    /// The name of the CWE check.
    pub name: &'static str,
    /// The version number of the CWE check.
    /// Should be incremented whenever significant changes are made to the check.
    pub version: &'static str,
    /// The function that executes the check and returns CWE warnings found during the check.
    pub run: CweModuleFn,
}

impl std::fmt::Display for CweModule {
    /// Print the module name and its version number.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, r#""{}": "{}""#, self.name, self.version)
    }
}

/// Get a list of all known analysis modules.
pub fn get_modules() -> Vec<&'static CweModule> {
    vec![
        &crate::checkers::cwe_78::CWE_MODULE,
        &crate::checkers::cwe_134::CWE_MODULE,
        &crate::checkers::cwe_190::CWE_MODULE,
        &crate::checkers::cwe_215::CWE_MODULE,
        &crate::checkers::cwe_243::CWE_MODULE,
        &crate::checkers::cwe_332::CWE_MODULE,
        &crate::checkers::cwe_367::CWE_MODULE,
        &crate::checkers::cwe_426::CWE_MODULE,
        &crate::checkers::cwe_467::CWE_MODULE,
        &crate::checkers::cwe_476::CWE_MODULE,
        &crate::checkers::cwe_560::CWE_MODULE,
        &crate::checkers::cwe_676::CWE_MODULE,
        &crate::checkers::cwe_782::CWE_MODULE,
        &crate::analysis::pointer_inference::CWE_MODULE,
    ]
}

/// A struct containing pointers to all known analysis results
/// that may be needed as input for other analyses and CWE checks.
#[derive(Clone, Copy)]
pub struct AnalysisResults<'a> {
    /// The content of the binary file
    pub binary: &'a [u8],
    /// A representation of the runtime memory image of the binary.
    pub runtime_memory_image: &'a RuntimeMemoryImage,
    /// The computed control flow graph of the program.
    pub control_flow_graph: &'a Graph<'a>,
    /// A pointer to the project struct
    pub project: &'a Project,
    /// The results of the function signature analysis if already computed.
    pub function_signatures: Option<&'a BTreeMap<Tid, FunctionSignature>>,
    /// The result of the pointer inference analysis if already computed.
    pub pointer_inference: Option<&'a PointerInference<'a>>,
    /// The result of the string abstraction if already computed.
    pub string_abstraction: Option<&'a StringAbstraction<'a, BricksDomain>>,
}

impl<'a> AnalysisResults<'a> {
    /// Create a new `AnalysisResults` struct with only the project itself known.
    pub fn new(
        binary: &'a [u8],
        runtime_memory_image: &'a RuntimeMemoryImage,
        control_flow_graph: &'a Graph<'a>,
        project: &'a Project,
    ) -> AnalysisResults<'a> {
        AnalysisResults {
            binary,
            runtime_memory_image,
            control_flow_graph,
            project,
            function_signatures: None,
            pointer_inference: None,
            string_abstraction: None,
        }
    }

    /// Compute the function signatures for internal functions.
    pub fn compute_function_signatures(
        &self,
    ) -> (BTreeMap<Tid, FunctionSignature>, Vec<LogMessage>) {
        analysis::function_signature::compute_function_signatures(
            self.project,
            self.control_flow_graph,
        )
    }

    /// Create a new `AnalysisResults` struct containing the given function signature analysis results.
    pub fn with_function_signatures(
        self,
        function_signatures: Option<&'a BTreeMap<Tid, FunctionSignature>>,
    ) -> AnalysisResults<'a> {
        AnalysisResults {
            function_signatures,
            ..self
        }
    }

    /// Compute the pointer inference analysis.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_pointer_inference(
        &'a self,
        config: &serde_json::Value,
        print_stats: bool,
    ) -> PointerInference<'a> {
        crate::analysis::pointer_inference::run(
            self.project,
            self.runtime_memory_image,
            self.control_flow_graph,
            serde_json::from_value(config.clone()).unwrap(),
            false,
            print_stats,
        )
    }

    /// Create a new `AnalysisResults` struct containing the given pointer inference analysis results.
    pub fn with_pointer_inference<'b: 'a>(
        self,
        pi_results: Option<&'b PointerInference<'a>>,
    ) -> AnalysisResults<'b> {
        AnalysisResults {
            pointer_inference: pi_results,
            ..self
        }
    }

    /// Compute the string abstraction.
    /// As the string abstraction depends on the pointer inference, the
    /// pointer inference is also computed and put into the `AnalysisResults` struct.
    /// The result gets returned, but not saved to the `AnalysisResults` struct itself.
    pub fn compute_string_abstraction(
        &'a self,
        config: &serde_json::Value,
        pi_results: Option<&'a PointerInference<'a>>,
    ) -> StringAbstraction<BricksDomain> {
        crate::analysis::string_abstraction::run(
            self.project,
            self.runtime_memory_image,
            self.control_flow_graph,
            pi_results.unwrap(),
            serde_json::from_value(config.clone()).unwrap(),
        )
    }

    /// Create a new `AnalysisResults` struct containing the given string abstraction results.
    pub fn with_string_abstraction<'b: 'a>(
        self,
        string_abstraction: Option<&'b StringAbstraction<'a, BricksDomain>>,
    ) -> AnalysisResults<'b> {
        AnalysisResults {
            string_abstraction,
            ..self
        }
    }
}
