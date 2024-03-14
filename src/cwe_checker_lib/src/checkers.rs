//! The implemented CWE checks.
//! See their module descriptions for detailed information about each check.
//!
//! Currently the **Memory** check is not contained in this module
//! but directly incorporated into the [`pointer_inference`](crate::analysis::pointer_inference) module.
//! See there for detailed information about this check.

/// Checkers that are supported for Linux kernel modules.
pub const MODULES_LKM: [&str; 9] = [
    "CWE134", "CWE190", "CWE215", "CWE416", "CWE457", "CWE467", "CWE476", "CWE676", "CWE789",
];

pub mod cwe_119;
pub mod cwe_134;
pub mod cwe_190;
pub mod cwe_215;
pub mod cwe_243;
pub mod cwe_252;
pub mod cwe_332;
pub mod cwe_337;
pub mod cwe_367;
pub mod cwe_416;
pub mod cwe_426;
pub mod cwe_467;
pub mod cwe_476;
pub mod cwe_560;
pub mod cwe_676;
pub mod cwe_78;
pub mod cwe_782;
pub mod cwe_789;
