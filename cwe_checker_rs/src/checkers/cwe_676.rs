/// The CWE 676 checks for potentially dangerous function calls, such as strcpy, memcpy, scanf etc.

use crate::{
    intermediate_representation::{ Program, Project, Sub, Term, Tid, Jmp, ExternSymbol }, 
    utils::log::{ CweWarning, LogMessage }};
use serde::{ Serialize, Deserialize };

const VERSION: &str = "0.1";

pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "CWE676",
    version: VERSION,
    run: check_cwe,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}


/// For each block of a subroutine check if the jump is a direct call and if the target TID of that call is equal to a dangerous symbol TID
pub fn get_call_to_target<'a>(caller: &'a Term<Sub>, target: &'a ExternSymbol) -> Vec<Option<(&'a str, &'a Tid, &'a str)>> {
    let mut calls: Vec<Option<(&'a str, &'a Tid, &'a str)>> = Vec::new();
    for blk in caller.term.blocks.iter() {
        for jmp in blk.term.jmps.iter() {
            match &jmp.term {
                Jmp::Call{ target: dst, .. } => {
                    if *dst == target.tid {
                        calls.push(Some((caller.term.name.as_str(), &blk.tid, target.name.as_str())));
                    }
                }
                _ => ()
            }
        }
    }

    calls
}


/// For each subroutine and each found dangerous symbol, check for calls to the corresponding symbol
pub fn get_calls_to_symbols<'a>(subfunctions: &'a Vec<Term<Sub>>, dangerous_symbols: &'a Vec<&'a ExternSymbol>) -> Vec<Option<(&'a str, &'a Tid, &'a str)>> {
    let mut calls: Vec<Option<(&str, &Tid, &str)>> = Vec::new();
    for sub in subfunctions.iter() {
        for symbol in dangerous_symbols.iter() {
            calls.append(&mut get_call_to_target(sub, symbol))
        }
    }

    calls
}


/// Generate cwe warnings for potentially dangerous function calls
pub fn generate_cwe_warnings<'a>(dangerous_calls: Vec<Option<(&'a str, &'a Tid, &'a str)>>) -> Vec<CweWarning> {
    let mut cwe_warnings: Vec<CweWarning> = Vec::new();
    for call in dangerous_calls.iter() {
        match *call {
            Some((sub_name, blk_tid, target_name)) => {
                let address: &String = &blk_tid.address;
                let description: String = format!("(Use of Potentially Dangerous Function) {} ({}) -> {}",
                    sub_name,
                    address,
                    target_name
                );
                let cwe_warning = CweWarning::new(
                    String::from(CWE_MODULE.name),
                    String::from(CWE_MODULE.version),
                    description,
                )
                    .addresses(vec![address.clone()])
                    .tids(vec![format!("{}", blk_tid)])
                    .symbols(vec![String::from(sub_name)])
                    .other(vec![vec![String::from("dangerous_function"), String::from(target_name)]]);

                cwe_warnings.push(cwe_warning);
            },
            _ => ()
        }
    }

    cwe_warnings
}


/// Filter external symbols by dangerous symbols
pub fn resolve_symbols<'a>(external_symbols: &'a Vec<ExternSymbol>, symbols: &'a Vec<String>) -> Vec<&'a ExternSymbol> {
    external_symbols
        .iter()
        .filter(|symbol| symbols.iter().any(|dangerous_function| *symbol.name == *dangerous_function))
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