//! This crate contains acceptance tests for the cwe_checker.

use colored::*;
use std::process::Command;

/// CPU architectures contained in the test samples.
pub const ARCHITECTURES: &[&str] = &[
    "aarch64", "arm", "mips64", "mips64el", "mips", "mipsel", "ppc64", "ppc64le", "ppc", "x64",
    "x86", "riscv64",
];
/// Compilers contained in the test samples
pub const COMPILERS: &[&str] = &["gcc", "clang"];
/// CPU architectures for the Windows-based test samples
pub const WINDOWS_ARCHITECTURES: &[&str] = &["x64", "x86"];
/// Compilers used for the Windows-based test samples
pub const WINDOWS_COMPILERS: &[&str] = &["mingw32-gcc"];
/// CPU architectures that are supported for Linux kernel modules.
pub const LKM_ARCHITECTURES: &[&str] = &["aarch64"];
/// Compilers used for the Linux kernel module test samples.
pub const LKM_COMPILERS: &[&str] = &["clang"];
/// CWEs that are supported for Linux kernel modules.
pub const LKM_CWE: &[&str] = &["cwe_252", "cwe_467", "cwe_476", "cwe_676"];

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
    /// True iff the test binary is a Linux kernel module.
    is_lkm: bool,
}

mod helpers {
    pub fn cwd() -> String {
        std::env::current_dir()
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    }
}

impl CweTestCase {
    /// Get the full path of the test binary.
    fn get_filepath(&self) -> String {
        if self.is_lkm {
            format!(
                "{}/lkm_samples/build/{}_{}_{}.ko",
                helpers::cwd(),
                self.cwe,
                self.architecture,
                self.compiler
            )
        } else {
            format!(
                "{}/artificial_samples/build/{}_{}_{}.out",
                helpers::cwd(),
                self.cwe,
                self.architecture,
                self.compiler
            )
        }
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
        let output = if cfg!(feature = "docker") {
            const DOCKER_MEMORY_GIB: u64 = 8;
            const DOCKER_CPUS: u64 = 1;

            let mut cmd = Command::new("docker");
            cmd.arg("run");
            cmd.arg("--rm");
            cmd.arg("-i");
            cmd.arg("--memory");
            cmd.arg(format!("{}g", DOCKER_MEMORY_GIB));
            cmd.arg(format!("--cpus={}.0", DOCKER_CPUS));
            cmd.arg("-v");
            cmd.arg(format!("{}:/a/target", filepath));

            cmd.arg("cwe_checker");
            cmd.arg("--partial");
            cmd.arg(self.check_name);
            cmd.arg("--quiet");
            // Placing target at `/` makes Ghidra crash on PE files...
            cmd.arg("/a/target");

            cmd.output().unwrap()
        } else {
            Command::new("cwe_checker")
                .arg(&filepath)
                .arg("--partial")
                .arg(self.check_name)
                .arg("--quiet")
                .output()
                .unwrap()
        };
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
    mark_skipped_closure(test_cases, |test| test.architecture == arch)
}

/// Mark test cases using the given compiler as `skipped`.
pub fn mark_compiler_skipped(test_cases: &mut [CweTestCase], comp: &str) {
    mark_skipped_closure(test_cases, |test| test.compiler == comp)
}

/// Mark test cases using the given CPU architecture + compiler combination as `skipped`.
pub fn mark_skipped(test_cases: &mut [CweTestCase], value1: &str, value2: &str) {
    mark_skipped_closure(test_cases, |test| {
        (test.architecture == value1 && test.compiler == value2)
            || (test.architecture == value2 && test.compiler == value1)
    })
}

/// Mark test cases using the given CPU architecture + compiler combination as `skipped`
/// iff they are not Linux kernel modules.
pub fn mark_skipped_user(test_cases: &mut [CweTestCase], value1: &str, value2: &str) {
    mark_skipped_closure(test_cases, |test| {
        !test.is_lkm
            && ((test.architecture == value1 && test.compiler == value2)
                || (test.architecture == value2 && test.compiler == value1))
    })
}

/// Marks all test cases for which the given callback returns true as `skipped`.
fn mark_skipped_closure<F>(test_cases: &mut [CweTestCase], predicate: F)
where
    F: Fn(&CweTestCase) -> bool,
{
    for test in test_cases.iter_mut() {
        if predicate(test) {
            test.skipped = true;
        }
    }
}

/// Return a list with all possible Linux test cases for the given CWE.
pub fn linux_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    new_test_cases(cwe, ARCHITECTURES, COMPILERS, check_name, false)
        .into_iter()
        .filter(|test| test.architecture != "ppc" || test.compiler != "clang")
        .collect()
}

/// Return a list with all possible Windows test cases for the given CWE
pub fn windows_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    new_test_cases(
        cwe,
        WINDOWS_ARCHITECTURES,
        WINDOWS_COMPILERS,
        check_name,
        false,
    )
}

/// Returns a list with all possible Linux kernel module test cases for the
/// given CWE.
pub fn lkm_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    if LKM_CWE.contains(&cwe) {
        new_test_cases(cwe, LKM_ARCHITECTURES, LKM_COMPILERS, check_name, true)
    } else {
        Vec::new()
    }
}

/// Generate test cases for all combinations of CPU architecture and compiler given.
pub fn new_test_cases(
    cwe: &'static str,
    architectures: &[&'static str],
    compilers: &[&'static str],
    check_name: &'static str,
    is_lkm: bool,
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
                is_lkm,
            });
        }
    }
    vec
}

/// Return a list of all possible test cases (Linux and Windows) for the given CWE.
pub fn all_test_cases(cwe: &'static str, check_name: &'static str) -> Vec<CweTestCase> {
    let mut vec = linux_test_cases(cwe, check_name);
    vec.append(&mut windows_test_cases(cwe, check_name));
    vec.append(&mut lkm_test_cases(cwe, check_name));
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

    macro_rules! run_tests {
        // Not differentiating between user and lkm expected occurrences.
        (
            $tests:expr,
            $default_num:literal,
            $cwe:literal$(,)?
            $((
                    $arch:literal,
                    $comp:literal,
                    $num: literal$(,)?
            )),*$(,)?
        ) => {
            run_tests!(
                $tests,
                user: $default_num,
                lkm: $default_num,
                $cwe,
                $((
                    $arch,
                    $comp,
                    user: $num,
                    lkm: $num,
                ),)*
            );
        };
        (
            $tests:expr,
            user: $default_num_user:literal,
            lkm: $default_num_lkm:literal,
            $cwe:literal,
            $((
                    $arch:literal,
                    $comp:literal,
                    user: $num_user:literal,
                    lkm: $num_lkm: literal$(,)?
            )),*$(,)?
        ) => {
            let mut error_log = Vec::new();

            for test_case in $tests {
                let num_expected_occurences =
                    match (test_case.architecture, test_case.compiler) {
                        $(
                            ($arch, $comp) => {
                                if test_case.is_lkm {
                                    $num_lkm
                                } else {
                                    $num_user
                                }
                            },
                        )*
                        _ => {
                            if test_case.is_lkm {
                                $default_num_lkm
                            } else {
                                $default_num_user
                            }
                        }
                };

                if let Err(error) = test_case.run_test($cwe, num_expected_occurences) {
                    error_log.push((test_case.get_filepath(), error));
                }
            }

            if !error_log.is_empty() {
                print_errors(error_log);
                panic!();
            }
        };
    }

    #[test]
    #[ignore]
    fn bare_metal() {
        let bin_path = format!("/{}/bare_metal_samples/test_sample.bin", helpers::cwd());
        let config_path = format!("/{}/../bare_metal/stm32f407vg.json", helpers::cwd());

        let mut cmd = if cfg!(feature = "docker") {
            let mut cmd = Command::new("docker");
            cmd.arg("run");
            cmd.arg("--rm");
            cmd.arg("-i");
            cmd.arg("-v");
            cmd.arg(format!("{}:{}", &bin_path, &bin_path));
            cmd.arg("-v");
            cmd.arg(format!("{}:{}", &config_path, &config_path));
            cmd.arg("cwe_checker");
            cmd
        } else {
            Command::new("cwe_checker")
        };

        let output = cmd
            .arg(&bin_path)
            .arg("--partial")
            .arg("Memory")
            .arg("--quiet")
            .arg("--bare-metal-config")
            .arg(&config_path)
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
            println!("{} \t {}", bin_path, "[OK]".green());
        } else {
            println!("{} \t {}", bin_path, "[FAILED]".red());
            panic!(
                "Expected occurrences: Between 1 and 10. Found: {}",
                num_cwes
            );
        }
    }

    #[test]
    #[ignore]
    fn cwe_78() {
        let mut tests = all_test_cases("cwe_78", "CWE78");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Investigate.
        mark_architecture_skipped(&mut tests, "ppc");

        // Return value detection insufficient for x86.
        mark_architecture_skipped(&mut tests, "x86");

        // Pointer Inference returns insufficient results for PE
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE78]");
    }

    /// Regression test: Calls to `scanf` and `sscanf` must not crash the
    /// pcode-to-IR translation. The input passed through `sscanf` to `system`
    /// should be detected as CWE-78.
    #[test]
    #[ignore]
    fn scanf_sscanf() {
        let tests = all_test_cases("scanf_sscanf", "CWE78");

        // CWE-78 is not detected, but the analysis must not crash.
        run_tests!(
            tests,
            1,
            "[CWE78]",
            ("mips64", "gcc", 0),
            ("mips64", "clang", 0),
            ("mips64el", "gcc", 0),
            ("mips64el", "clang", 0),
            ("ppc", "gcc", 0),
            ("ppc64", "gcc", 0),
            ("ppc64", "clang", 0),
            ("ppc64le", "gcc", 0),
            ("ppc64le", "clang", 0),
            ("x86", "gcc", 0),
            ("x86", "clang", 0),
            ("x64", "mingw32-gcc", 0),
            ("x86", "mingw32-gcc", 0),
        );
    }

    #[test]
    #[ignore]
    fn cwe_119() {
        let mut tests = all_test_cases("cwe_119", "CWE119");

        // TODO: Weird mixing of 64 and 32 bits.
        mark_architecture_skipped(&mut tests, "ppc");

        // TODO: Some stuff was certainly broken by Pcode refactoring!
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_architecture_skipped(&mut tests, "ppc64le");
        mark_architecture_skipped(&mut tests, "x86");
        mark_architecture_skipped(&mut tests, "x64");

        run_tests!(tests, 1, "[CWE119]");
    }

    #[test]
    #[ignore]
    fn cwe_125() {
        let mut tests = all_test_cases("cwe_119", "CWE119");

        // TODO: Weird mixing of 64 and 32 bits.
        mark_architecture_skipped(&mut tests, "ppc");

        // TODO: Some stuff was certainly broken by Pcode refactoring!
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_architecture_skipped(&mut tests, "ppc64le");
        mark_architecture_skipped(&mut tests, "x86");
        mark_architecture_skipped(&mut tests, "x64");

        run_tests!(tests, 2, "[CWE125]");
    }

    #[test]
    #[ignore]
    fn cwe_134() {
        let mut tests = all_test_cases("cwe_134", "CWE134");

        // TODO: No PI result.
        mark_skipped(&mut tests, "x86", "gcc");

        // TODO: Investigate.
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE134]");
    }

    #[test]
    #[ignore]
    fn cwe_190() {
        let mut tests = all_test_cases("cwe_190", "CWE190");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: No PI result.
        mark_skipped(&mut tests, "x86", "gcc");

        run_tests!(
            tests,
            3,
            "[CWE190]",
            // Multiplications get compiled to shifts.
            // TODO: Change test source code.
            ("x64", "gcc", 1),
            ("x64", "clang", 1),
            ("x64", "mingw32-gcc", 1),
            ("x86", "clang", 1),
            ("x86", "mingw32-gcc", 1),
        );
    }

    #[test]
    #[ignore]
    fn cwe_215() {
        // We use the test binaries of another check here.
        let mut tests = linux_test_cases("cwe_476", "CWE215");
        tests.extend(lkm_test_cases("cwe_476", "CWE215"));

        run_tests!(tests, 1, "[CWE215]");
    }

    #[test]
    #[ignore]
    fn cwe_243() {
        let tests = linux_test_cases("cwe_243", "CWE243");

        run_tests!(tests, 1, "[CWE243]");
    }

    #[test]
    #[ignore]
    fn cwe_252() {
        let mut tests = all_test_cases("cwe_252", "CWE252");

        // TODO: The Pcode refactoring has certainly broken some stuff here!
        mark_architecture_skipped(&mut tests, "ppc");
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_architecture_skipped(&mut tests, "ppc64le");
        mark_architecture_skipped(&mut tests, "riscv64");
        mark_architecture_skipped(&mut tests, "x86");
        mark_architecture_skipped(&mut tests, "x64");
        mark_architecture_skipped(&mut tests, "mips64");
        mark_architecture_skipped(&mut tests, "mips64el");
        mark_skipped(&mut tests, "mipsel", "gcc");
        mark_skipped(&mut tests, "mips", "gcc");

        run_tests!(
            tests,
            user: 9,
            lkm: 1,
            "[CWE252]",
        );
    }

    #[test]
    #[ignore]
    fn cwe_332() {
        let tests = all_test_cases("cwe_332", "CWE332");

        run_tests!(tests, 1, "[CWE332]");
    }

    #[test]
    #[ignore]
    fn cwe_337() {
        let mut tests = all_test_cases("cwe_337", "CWE337");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Investigate.
        mark_architecture_skipped(&mut tests, "x86");
        mark_skipped(&mut tests, "x64", "mingw32-gcc");

        run_tests!(tests, 1, "[CWE337]");
    }

    #[test]
    #[ignore]
    fn cwe_367() {
        let mut tests = all_test_cases("cwe_367", "CWE367");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Investigate.
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE367]");
    }

    #[test]
    #[ignore]
    fn cwe_415() {
        let mut tests = all_test_cases("cwe_415", "CWE416");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Investigate.
        mark_skipped(&mut tests, "ppc", "gcc");
        mark_skipped(&mut tests, "x86", "gcc");
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 2, "[CWE415]");
    }

    #[test]
    #[ignore]
    fn cwe_416() {
        let mut tests = all_test_cases("cwe_416", "CWE416");

        // TODO: Investigate.
        mark_skipped(&mut tests, "ppc", "gcc");
        mark_skipped(&mut tests, "x86", "gcc");
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE416]");
    }

    #[test]
    #[ignore]
    fn cwe_426() {
        let mut tests = all_test_cases("cwe_426", "CWE426");

        // Functions called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // Multiple entry points into vulnerable function.
        mark_skipped(&mut tests, "ppc64le", "clang");

        // Ghidra dies.
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE426]");
    }

    #[test]
    #[ignore]
    fn cwe_467() {
        let mut tests = all_test_cases("cwe_467", "CWE467");

        // Only one instance is found.
        // Other instance cannot be found, since the constant is not defined in
        // the basic block of the call instruction.
        mark_skipped_user(&mut tests, "aarch64", "clang");
        mark_skipped(&mut tests, "arm", "clang");
        mark_skipped(&mut tests, "riscv64", "clang");
        mark_skipped(&mut tests, "mips64", "clang");
        mark_skipped(&mut tests, "mips64el", "clang");
        mark_skipped(&mut tests, "mips", "clang");
        mark_skipped(&mut tests, "mipsel", "clang");

        // `strncmp` called via unrecognized stub.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Looks like it should work but it doesn't.
        mark_skipped(&mut tests, "ppc", "gcc");

        // TODO: Investigate.
        mark_skipped(&mut tests, "x64", "mingw32-gcc");

        run_tests!(tests, 2, "[CWE467]");
    }

    #[test]
    #[ignore]
    fn cwe_476() {
        let mut tests = all_test_cases("cwe_476", "CWE476");

        // `umask` called via unrecognized thunk.
        // Note: Multiple entry points are not an issue here since deduplication
        //   happens via addresses.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // No PI result after first block of function.
        mark_skipped(&mut tests, "x86", "gcc");

        // TODO: Investigate.
        mark_skipped(&mut tests, "x64", "mingw32-gcc");

        run_tests!(tests, 1, "[CWE476]");
    }

    #[test]
    #[ignore]
    fn cwe_560() {
        let mut tests = linux_test_cases("cwe_560", "CWE560");

        // `umask` called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        run_tests!(tests, 1, "[CWE560]");
    }

    #[test]
    #[ignore]
    fn cwe_676() {
        let mut tests = all_test_cases("cwe_676", "CWE676");

        // TODO: Investigate.
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 1, "[CWE676]", ("aarch64", "clang", 2));
    }

    #[test]
    #[ignore]
    fn cwe_782() {
        let tests = new_test_cases("cwe_782", &["x64"], COMPILERS, "CWE782", false);

        run_tests!(tests, 1, "[CWE782]");
    }

    #[test]
    #[ignore]
    fn cwe_787() {
        let mut tests = all_test_cases("cwe_119", "CWE119");

        mark_skipped(&mut tests, "arm", "gcc");
        mark_skipped(&mut tests, "mips64", "gcc");
        mark_skipped(&mut tests, "mips64el", "gcc");
        mark_architecture_skipped(&mut tests, "mips");
        mark_architecture_skipped(&mut tests, "mipsel");
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_architecture_skipped(&mut tests, "ppc64le");
        // Weird mixing of 32 and 64 bit.
        mark_skipped(&mut tests, "ppc", "gcc");
        mark_skipped(&mut tests, "x86", "gcc");
        mark_architecture_skipped(&mut tests, "riscv64");
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        run_tests!(tests, 2, "[CWE787]");
    }

    #[test]
    #[ignore]
    fn cwe_789() {
        let mut tests = all_test_cases("cwe_789", "CWE789");

        // `malloc` called via unrecognized thunk.
        mark_architecture_skipped(&mut tests, "ppc64");
        mark_skipped(&mut tests, "ppc64le", "gcc");

        // TODO: Investigate.
        mark_compiler_skipped(&mut tests, "mingw32-gcc");

        // No PI result after first block of function.
        mark_skipped(&mut tests, "x86", "gcc");

        run_tests!(tests, 2, "[CWE789]");
    }
}
