use crate::intermediate_representation::Project;

const VERSION: &str = "0.1";

pub static CWE_MODULE: crate::CweModule = crate::CweModule {
    name: "CWE676",
    version: VERSION,
    run: check_cwe,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    dangerous_function_symbols: Vec<String>,
}


pub fn get_call_to_target() {

}


pub fn get_calls_to_target() {

}


pub fn print_calls() {

}


pub fn resolve_symbols(subfunctions: Vec<Term<Sub>>, symbols: Vec<String>) -> Vec<Term<Sub>> {
    subfunctions.retain(|&sub| symbols.iter().any(|&dangerous| sub.term.name == dangerous))
}


pub fn check_cwe(
    project: &Project,
    cwe_params: &serde_json::Value,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    run(project, config, false)
}

pub fn run(
    project: &Project,
    config: Config,
    print_debug: bool,
) -> (Vec<LogMessage>, Vec<CweWarning>) {
    let prog: Term<Program> = project.program;
    let subfunctions: Vec<Term<Sub>> = prog.subs;
    let dangerous_functions: Vec<Term<Sub>> = resolve_symbols(subfunctions, config.dangerous_function_symbols);

}