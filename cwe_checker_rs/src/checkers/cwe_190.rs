//! This module implements a check for CWE-190: Integer overflow or wraparound.
//!
//! An integer overflow can lead to undefined behaviour and is especially dangerous
//! in conjunction with memory management functions.
//!
//! See <https://cwe.mitre.org/data/definitions/190.html> for a detailed description.
//!
//! ## How the check works
//!
//! For each call to a function from the CWE190 symbol list we check whether the
//! basic block directly before the call contains a multiplication instruction.
//! If one is found, the call gets flagged as a CWE hit, as there is no overflow
//! check corresponding to the multiplication before the call. The default CWE190
//! symbol list contains the memory allocation functions *malloc*, *xmalloc*,
//! *calloc* and *realloc*. The list is configurable in config.json.
//!
//! ## False Positives
//!
//! - There is no check whether the result of the multiplication is actually used
//!   as input to the function call. However, this does not seem to generate a lot
//!   of false positives in practice.
//! - There is no value set analysis in place to determine whether an overflow is
//!   possible or not at the specific instruction.
//!
//! ## False Negatives
//!
//! - All integer overflows not in a basic block right before a call to a function
//! from the CWE190 symbol list.
//! - All integer overflows caused by addition or subtraction.

use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::{get_callsites, get_symbol_map};
use crate::CweModule;

pub static CWE_MODULE: CweModule = CweModule {
    name: "CWE190",
    version: "0.1",
    run: check_cwe,
};

/// The configuration struct.
/// The `symbols` are extern function names.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}

/// Check whether the given expression contains an integer multiplication subexpression,
/// i.e. an `IntMult` or `IntLeft` (left shift) binary operation.
fn expression_contains_multiplication(expr: &Expression) -> bool {
    use Expression::*;
    match expr {
        BinOp {
            op: BinOpType::IntMult,
            ..
        }
        | BinOp {
            op: BinOpType::IntLeft,
            ..
        } => true,
        Var(_) | Const(_) | Unknown { .. } => false,
        BinOp { lhs, rhs, .. } => {
            expression_contains_multiplication(lhs) || expression_contains_multiplication(rhs)
        }
        UnOp { arg, .. } | Cast { arg, .. } | Subpiece { arg, .. } => {
            expression_contains_multiplication(arg)
        }
    }
}

/// Check whether the given block contains a multiplication expression.
/// Expressions computing the address of a `Load` or `Store` instruction are ignored
/// since the addresses themselves cannot be inputs to the call at the end of the block.
fn block_contains_multiplication(block: &Term<Blk>) -> bool {
    block.term.defs.iter().any(|def| match &def.term {
        Def::Assign { value, .. } | Def::Store { value, .. } => {
            expression_contains_multiplication(value)
        }
        Def::Load { .. } => false,
    })
}

/// Generate the CWE warning for a detected instance of the CWE.
fn generate_cwe_warning(callsite: &Tid, called_symbol: &ExternSymbol) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(Integer Overflow or Wraparound) Potential overflow due to multiplication before call to {} at {}",
            called_symbol.name, callsite.address
        ))
        .tids(vec![format!("{}", callsite)])
        .addresses(vec![callsite.address.clone()])
        .symbols(vec!(called_symbol.name.clone()))
}

/// Run the CWE check.
/// For each call to one of the symbols configured in config.json
/// we check whether the block containing the call also contains a multiplication instruction.
pub fn check_cwe(
    project: &Project,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();
    let symbol_map = get_symbol_map(project, &config.symbols);
    for sub in project.program.term.subs.iter() {
        for (block, jump, symbol) in get_callsites(sub, &symbol_map) {
            if block_contains_multiplication(block) {
                cwe_warnings.push(generate_cwe_warning(&jump.tid, symbol));
            }
        }
    }

    (Vec::new(), cwe_warnings)
}
