use crate::{
    intermediate_representation::{ Project, Sub, Term, Program }, 
    utils::log::{ CweWarning, LogMessage }
};
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


pub fn get_call_to_target() {

}


pub fn get_calls_to_target() {

}


pub fn print_calls() {

}


pub fn resolve_symbols(subfunctions: &Vec<Term<Sub>>, symbols: &Vec<String>) -> Vec<Term<Sub>> {
    let mut filtered_subs = subfunctions.clone();
    filtered_subs.retain(|symbol| symbols.iter().any(|dangerous_function| *symbol.term.name == *dangerous_function));
    filtered_subs
}


pub fn check_cwe(
    project: &Project,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let prog: &Term<Program> = &project.program;
    let subfunctions: &Vec<Term<Sub>> = &prog.term.subs;
    let dangerous_functions = resolve_symbols(subfunctions, &config.symbols);

    (vec![], vec![])
}