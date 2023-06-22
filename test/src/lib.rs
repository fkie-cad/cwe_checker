//! This crate contains acceptance tests using Ghidra as a backend for the *cwe_checker*.

use colored::*;
use std::process::Command;

/// CPU architectures contained in the test samples
pub const ARCHITECTURES: &[&str] = &[
    "aarch64", "arm", "mips64", "mips64el", "mips", "mipsel", "ppc64", "ppc64le", "ppc", "x64",
    "x86",
];
/// Compilers contained in the test samples
pub const COMPILERS: &[&str] = &["gcc", "clang"];
/// CPU architectures for the Windows-based test samples
pub const WINDOWS_ARCHITECTURES: &[&str] = &["x64", "x86"];
/// Compilers used for the Windows-based test samples
pub const WINDOWS_COMPILERS: &[&str] = &["mingw32-gcc"];

/// A test case containing the necessary information to run an acceptance test.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CweTestCase {
    /// The name of the cwe (according to the test file)
    cwe: &'static str,
    /// The CPU architecture the test case was compiled for
    architecture: &'static str,
    /// The compiler used to compile the test case
    compiler: &'static str,
    /// The name of the *cwe_checker*-check to execute
    check_name: &'static str,
    /// Whether the test case should be skipped
    skipped: bool,
}

impl CweTestCase {
    /// Get the file path of the test binary
    fn get_filepath(&self) -> String {
        format!(
            "artificial_samples/build/{}_{}_{}.out",
            self.cwe, self.architecture, self.compiler
        )
    }

    /// Run the test case and print to the shell, whether the test case succeeded or not.
    /// Returns stdout + stderr of the test execution on failure.
    pub fn run_test(
        &self,
        search_string: &str,
        num_expected_occurences: usize,
    ) -> Result<(), String> {
        let filepath = self.get_filepath();
        if self.skipped {
            println!("{} \t {}", filepath, "[SKIPPED]".yellow());
            return Ok(());
        }
        let output = Command::new("cwe_checker")
            .arg(&filepath)
            .arg("--partial")
            .arg(self.check_name)
            .arg("--quiet")
            .output()
            .unwrap();
        if output.status.success() {
            let num_cwes = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter(|line| line.starts_with(search_string))
                .count();
            if num_cwes == num_expected_occurences {
                println!("{} \t {}", filepath, "[OK]".green());
                Ok(())
            } else {
                println!("{} \t {}", filepath, "[FAILED]".red());
                Err(format!(
                    "Expected occurrences: {num_expected_occurences}. Found: {num_cwes}"
                ))
            }
        } else {
            println!("{} \t {}", filepath, "[FAILED]".red());
            match output.status.code() {
                Some(_code) => Err(String::from_utf8(output.stdout).unwrap()
                    + &String::from_utf8(output.stderr).unwrap()),
                None => Err(format!("Execution failed for file {filepath}")),
            }
        }
    }
}

/// Mark test cases using the given CPU architecture as `skipped`.
pub fn mark_architecture_skipped(test_cases: &mut [CweTestCase], arch: &str) {
    for test in test_cases.iter_mut() {
        if test.architecture == arch {
            test.skipped = true;
        }
    }
}

/// Mark test cases using the given compiler as `skipped`.
pub fn mark_compiler_skipped(test_cases: &mut [CweTestCase], comp: &str) {
    for test in test_cases.iter_mut() {
        if test.compiler == comp {
            test.skipped = true;
        }
    }
}

/// Mark test cases using the given CPU architecture + compiler combination as `skipped`.
pub fn mark_skipped(test_cases: &mut [CweTestCase], value1: &str, value2: &str) {
    for test in test_cases.iter_mut() {
        if (test.architecture == value1 && test.compiler == value2)
            || (test.architecture == value2 && test.compiler == value1)
        {
            test.skipped = true;
        }
    }
}

/// Return a list with all possible Linux test cases for the given CWE.
pub fn linux_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    new_test_cases(cwe, ARCHITECTURES, COMPILERS, check_name)
        .into_iter()
        .filter(|test| test.architecture != "ppc" || test.compiler != "clang")
        .collect()
}

/// Return a list with all possible Windows test cases for the given CWE
pub fn windows_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    new_test_cases(cwe, WINDOWS_ARCHITECTURES, WINDOWS_COMPILERS, check_name)
}

/// Generate test cases for all combinations of CPU architecture and compiler given.
pub fn new_test_cases(
    cwe: &'static str,
    architectures: &[&'static str],
    compilers: &[&'static str],
    check_name: &'static str,
) -> Vec<CweTestCase> {
    let mut vec = Vec::new();
    for architecture in architectures {
        for compiler in compilers {
            vec.push(CweTestCase {
                cwe,
                architecture,
                compiler,
                check_name,
                skipped: false,
            });
        }
    }
    vec
}

/// Return a list of all possible test cases (Linux and Windows) for the given CWE.
pub fn all_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    let mut vec = linux_test_cases(cwe, check_name);
    vec.append(&mut windows_test_cases(cwe, check_name));
    vec
}

/// Print the error messages of failed checks.
/// The `error_log` tuples are of the form `(check_filename, error_message)`.
pub fn print_errors(error_log: Vec<(String, String)>) {
    for (filepath, error) in error_log {
        println!("{}", format!("+++ Error for {filepath} +++").red());
        println!("{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn bare_metal() {
        let filepath = "bare_metal_samples/test_sample.bin";
        let output = Command::new("cwe_checker")
            .arg(filepath)
            .arg("--partial")
            .arg("Memory")
            .arg("--quiet")
            .arg("--bare-metal-config")
            .arg("../bare_metal/stm32f407vg.json")
            .output()
            .unwrap();
        let num_cwes = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("[CWE476]"))
            .count();
        // We check the number of found CWEs only approximately
        // so that this check does not fail on minor result changes.
        // The results are not yet reliable enough for a stricter check.
        if num_cwes >= 1 && num_cwes <= 10 {
            println!("{} \t {}", filepath, "[OK]".green());
        } else {
            println!("{} \t {}", filepath, "[FAILED]".red());
            panic!(
                "Expected occurrences: Between 1 and 10. Found: {}",
                num_cwes
            );
        }
    }

    #[test]
    #[ignore]
    fn cwe_78() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_78", "CWE78");

        // Ghidra does not recognize all extern function calls in the disassembly step for MIPS.
        // Needs own control flow graph analysis to be fixed.
        mark_architecture_skipped(&mut tests, "mips64");
        mark_architecture_skipped(&mut tests, "mips64el");
        mark_architecture_skipped(&mut tests, "mips");
        mark_architecture_skipped(&mut tests, "mipsel");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "x86", "gcc");
        mark_skipped(&mut tests, "x86", "clang"); // Return value detection insufficient for x86
        mark_skipped(&mut tests, "arm", "clang"); // Loss of stack pointer position
        mark_skipped(&mut tests, "aarch64", "clang"); // Loss of stack pointer position

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // Pointer Inference returns insufficient results for PE

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE78]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_119() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_119", "CWE119");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE119]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_125() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_119", "CWE119");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "ppc", "gcc"); // Needs tracking of linear dependencies between register values.

        mark_skipped(&mut tests, "x86", "gcc"); // Unrelated third CWE hit in `__libc_csu_init`
        mark_skipped(&mut tests, "x86", "clang"); // Unrelated third CWE hit in `__libc_csu_init`

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 2;
            if let Err(error) = test_case.run_test("[CWE125]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_134() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_134", "CWE134");

        mark_architecture_skipped(&mut tests, "ppc64"); // TODO: Check reason for failure!
        mark_skipped(&mut tests, "ppc64le", "clang"); // TODO: Check reason for failure!

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE134]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_190() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_190", "CWE190");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 3;
            if let Err(error) = test_case.run_test("[CWE190]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_215() {
        let mut error_log = Vec::new();
        let tests = linux_test_cases("cwe_476", "CWE215"); // We use the test binaries of another check here.

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE215]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_243() {
        let mut error_log = Vec::new();
        let mut tests = linux_test_cases("cwe_243", "CWE243");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE243]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_332() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_332", "CWE332");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE332]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_367() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_367", "CWE367");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "x86", "mingw32-gcc"); // Symbol names are prefixed with an underscore in the Ghidra output.

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE367]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_415() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_415", "CWE416");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "x86", "mingw32-gcc"); // TODO: Check reason for failure! Probably same as above?

        for test_case in tests {
            let num_expected_occurences = 2;
            if let Err(error) = test_case.run_test("[CWE415]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_416() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_416", "CWE416");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "x86", "mingw32-gcc"); // TODO: Check reason for failure! Probably same as above?

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE416]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_426() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_426", "CWE426");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE426]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_467() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_467", "CWE467");

        // Only one instance is found.
        // Other instance cannot be found, since the constant is not defined in the basic block of the call instruction.
        mark_skipped(&mut tests, "aarch64", "clang");
        mark_skipped(&mut tests, "arm", "clang");
        mark_skipped(&mut tests, "mips", "clang");
        mark_skipped(&mut tests, "mipsel", "clang");
        mark_skipped(&mut tests, "mips64", "clang");
        mark_skipped(&mut tests, "mips64el", "clang");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 2;
            if let Err(error) = test_case.run_test("[CWE467]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_476() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_476", "CWE476");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE476]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_560() {
        let mut error_log = Vec::new();
        let mut tests = linux_test_cases("cwe_560", "CWE560");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE560]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_676() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_676", "CWE676");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.
        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            if test_case.architecture == "aarch64" && test_case.compiler == "clang" {
                // For some reason clang adds an extra `memcpy` here, which is also in the list of dangerous functions.
                let num_expected_occurences = 2;
                if let Err(error) = test_case.run_test("[CWE676]", num_expected_occurences) {
                    error_log.push((test_case.get_filepath(), error));
                }
            } else {
                let num_expected_occurences = 1;
                if let Err(error) = test_case.run_test("[CWE676]", num_expected_occurences) {
                    error_log.push((test_case.get_filepath(), error));
                }
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_782() {
        let mut error_log = Vec::new();
        let tests = new_test_cases("cwe_782", &["x64"], COMPILERS, "CWE782");
        for test_case in tests {
            let num_expected_occurences = 1;
            if let Err(error) = test_case.run_test("[CWE782]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_787() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_119", "CWE119");

        mark_skipped(&mut tests, "arm", "gcc"); // Needs tracking of linear dependencies between register values.
        mark_skipped(&mut tests, "mips64", "gcc"); // Needs tracking of linear dependencies between register values.
        mark_skipped(&mut tests, "mips64el", "gcc"); // Needs tracking of linear dependencies between register values.

        mark_architecture_skipped(&mut tests, "mips"); // Needs tracking of linear dependencies between register values.
        mark_architecture_skipped(&mut tests, "mipsel"); // Needs tracking of linear dependencies between register values.

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_skipped(&mut tests, "ppc", "gcc"); // Needs tracking of linear dependencies between register values.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 2;
            if let Err(error) = test_case.run_test("[CWE787]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
            panic!();
        }
    }

    #[test]
    #[ignore]
    fn cwe_789() {
        let mut error_log = Vec::new();
        let mut tests = all_test_cases("cwe_789", "CWE789");

        mark_architecture_skipped(&mut tests, "ppc64"); // Ghidra generates mangled function names here for some reason.
        mark_architecture_skipped(&mut tests, "ppc64le"); // Ghidra generates mangled function names here for some reason.

        mark_compiler_skipped(&mut tests, "mingw32-gcc"); // TODO: Check reason for failure!

        for test_case in tests {
            let num_expected_occurences = 2;
            if let Err(error) = test_case.run_test("[CWE789]", num_expected_occurences) {
                error_log.push((test_case.get_filepath(), error));
            }
        }
        if !error_log.is_empty() {
            print_errors(error_log);
        }
    }
}
