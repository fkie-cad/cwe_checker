//! This module implements a check for CWE-190: Integer overflow or wraparound.
//!
//! An integer overflow can lead to undefined behavior and is especially dangerous
//! in conjunction with memory management functions.
//!
//! See <https://cwe.mitre.org/data/definitions/190.html> for a detailed description.
//!
//! ## How the check works
//!
//! For each call to a function from the CWE190 symbol list we check whether the
//! basic block directly before the call contains a multiplication instruction.
//! If one is found, the call gets flagged as a CWE hit, as there is no overflow
//! check corresponding to the multiplication before the call as well as
//! the Pointer Inference can not exclude an overflow. The default CWE190
//! symbol list contains the memory allocation functions *malloc*, *xmalloc*,
//! *calloc* and *realloc*. The list is configurable in config.json.
//!
//! ## False Positives
//!
//! - There is no check whether the result of the multiplication is actually used
//!   as input to the function call. However, this does not seem to generate a lot
//!   of false positives in practice.
//! - Values that are not absolute e.g. user controlled or depend on other values.
//!
//! ## False Negatives
//!
//! - All integer overflows not in a basic block right before a call to a function
//! from the CWE190 symbol list.
//! - All integer overflows caused by addition or subtraction.

use crate::abstract_domain::AbstractDomain;
use crate::abstract_domain::DataDomain;
use crate::abstract_domain::IntervalDomain;
use crate::abstract_domain::RegisterDomain;
use crate::analysis::pointer_inference::*;
use crate::analysis::vsa_results::*;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::{CweWarning, LogMessage};
use crate::utils::symbol_utils::{get_callsites, get_symbol_map};
use crate::CweModule;

/// The module name and version
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
        .tids(vec![format!("{callsite}")])
        .addresses(vec![callsite.address.clone()])
        .symbols(vec![called_symbol.name.clone()])
}

/// Determines if all parameters are only absolute values and their included intervals are not top valued.
fn contains_top_value(pir: &PointerInference, jmp_tid: &Tid, parms: Vec<&Arg>) -> bool {
    for arg in parms {
        if let Some(value) = pir.eval_parameter_arg_at_call(jmp_tid, arg) {
            if !contains_only_non_top_absolute_value(&value) {
                return true;
            }
        }
    }
    false
}

/// Checks if the multiplication of element count and size parameters result in an overflow.
fn calloc_parm_mul_is_top(pir: &PointerInference, jmp_tid: &Tid, parms: Vec<&Arg>) -> bool {
    if let (Some(nmeb), Some(size)) = (
        pir.eval_parameter_arg_at_call(jmp_tid, parms[0]),
        pir.eval_parameter_arg_at_call(jmp_tid, parms[1]),
    ) {
        return !contains_only_non_top_absolute_value(&nmeb.bin_op(BinOpType::IntMult, &size));
    }

    false
}

/// Determines if the data domain only has absolute values and their included interval is not top valued.
fn contains_only_non_top_absolute_value(data_domain: &DataDomain<IntervalDomain>) -> bool {
    if let Some(interval) = data_domain.get_if_absolute_value() {
        if !interval.is_top() {
            return true;
        }
    }
    false
}

/// Run the CWE check.
/// For each call to one of the symbols configured in config.json
/// we check whether the block containing the call also contains a multiplication instruction.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let project = analysis_results.project;
    let pointer_inference_results = analysis_results.pointer_inference.unwrap();

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let mut cwe_warnings = Vec::new();
    let symbol_map = get_symbol_map(project, &config.symbols);
    for sub in project.program.term.subs.values() {
        for (block, jump, symbol) in get_callsites(sub, &symbol_map) {
            if block_contains_multiplication(block) {
                let parms = match symbol.name.as_str() {
                    "calloc" => {
                        if calloc_parm_mul_is_top(
                            pointer_inference_results,
                            &jump.tid,
                            vec![&symbol.parameters[0], &symbol.parameters[1]],
                        ) {
                            cwe_warnings.push(generate_cwe_warning(&jump.tid, symbol));
                        };
                        vec![&symbol.parameters[0], &symbol.parameters[1]]
                    }
                    "realloc" => vec![&symbol.parameters[1]],
                    _ => symbol.parameters.iter().collect(),
                };

                if contains_top_value(pointer_inference_results, &jump.tid, parms) {
                    cwe_warnings.push(generate_cwe_warning(&jump.tid, symbol));
                }
            }
        }
    }

    (Vec::new(), cwe_warnings)
}
