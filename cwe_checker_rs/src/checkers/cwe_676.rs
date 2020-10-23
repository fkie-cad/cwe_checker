//! The CWE 676 checks for potentially dangerous function calls, such as strcpy, memcpy, scanf etc.
use std::collections::HashMap;

use crate::{
    intermediate_representation::{ExternSymbol, Jmp, Program, Project, Sub, Term, Tid},
    utils::log::{CweWarning, LogMessage},
};
use serde::{Deserialize, Serialize};

const VERSION: &str = "0.1";

pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "CWE676",
    version: VERSION,
    run: check_cwe,
};

/// struct containing dangerous symbols from config.json
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}

/// For each block of a subroutine check if the jump is a direct call and if the target TID of that call is equal to a dangerous symbol TID
pub fn get_call_to_target<'a, 'b>(
    caller: &'a Term<Sub>,
    targets: &'b HashMap<&'a Tid, &'a str>,
) -> Vec<(&'a str, &'a Tid, &'a str)> {
    let mut calls: Vec<(&'a str, &'a Tid, &'a str)> = Vec::new();
    for blk in caller.term.blocks.iter() {
        for jmp in blk.term.jmps.iter() {
            match &jmp.term {
                Jmp::Call { target: dst, .. } => {
                    if targets.contains_key(dst) {
                        calls.push((
                            caller.term.name.as_str(),
                            &jmp.tid,
                            targets.get(dst).clone().unwrap(),
                        ));
                    }
                }
                _ => (),
            }
        }
    }

    calls
}

/// For each subroutine and each found dangerous symbol, check for calls to the corresponding symbol
pub fn get_calls_to_symbols<'a>(
    subfunctions: &'a Vec<Term<Sub>>,
    dangerous_symbols: &'a Vec<&'a ExternSymbol>,
) -> Vec<(&'a str, &'a Tid, &'a str)> {
    let mut calls: Vec<(&str, &Tid, &str)> = Vec::new();
    let mut symbol_map: HashMap<&Tid, &str> = HashMap::with_capacity(dangerous_symbols.len());
    for symbol in dangerous_symbols.iter() {
        symbol_map.insert(&symbol.tid, &symbol.name.as_str());
    }
    for sub in subfunctions.iter() {
        calls.append(&mut get_call_to_target(sub, &symbol_map));
    }

    calls
}

/// Generate cwe warnings for potentially dangerous function calls
pub fn generate_cwe_warnings<'a>(
    dangerous_calls: Vec<(&'a str, &'a Tid, &'a str)>,
) -> Vec<CweWarning> {
    let mut cwe_warnings: Vec<CweWarning> = Vec::new();
    for (sub_name, blk_tid, target_name) in dangerous_calls.iter() {
        let address: &String = &blk_tid.address;
        let description: String = format!(
            "(Use of Potentially Dangerous Function) {} ({}) -> {}",
            sub_name, address, target_name
        );
        let cwe_warning = CweWarning::new(
            String::from(CWE_MODULE.name),
            String::from(CWE_MODULE.version),
            description,
        )
        .addresses(vec![address.clone()])
        .tids(vec![format!("{}", blk_tid)])
        .symbols(vec![String::from(*sub_name)])
        .other(vec![vec![
            String::from("dangerous_function"),
            String::from(*target_name),
        ]]);

        cwe_warnings.push(cwe_warning);
    }

    cwe_warnings
}

/// Filter external symbols by dangerous symbols
pub fn resolve_symbols<'a>(
    external_symbols: &'a Vec<ExternSymbol>,
    symbols: &'a Vec<String>,
) -> Vec<&'a ExternSymbol> {
    external_symbols
        .iter()
        .filter(|symbol| {
            symbols
                .iter()
                .any(|dangerous_function| *symbol.name == *dangerous_function)
        })
        .collect()
}

pub fn check_cwe(
    project: &Project,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let prog: &Term<Program> = &project.program;
    let subfunctions: &Vec<Term<Sub>> = &prog.term.subs;
    let external_symbols: &Vec<ExternSymbol> = &prog.term.extern_symbols;
    let dangerous_symbols = resolve_symbols(external_symbols, &config.symbols);
    let dangerous_calls = get_calls_to_symbols(subfunctions, &dangerous_symbols);

    (vec![], generate_cwe_warnings(dangerous_calls))
}
