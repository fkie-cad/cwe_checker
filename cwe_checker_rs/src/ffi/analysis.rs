use super::serde::JsonBuilder;
use super::OcamlSendable;
use crate::term::*;
use crate::utils::log::CweWarning;

use super::failwith_on_panic;

fn run_pointer_inference(program_jsonbuilder_val: ocaml::Value) -> (Vec<CweWarning>, Vec<String>) {
    let json_builder = unsafe { JsonBuilder::from_ocaml(&program_jsonbuilder_val) };
    let program_json = serde_json::Value::from(json_builder);
    let mut project: Project =
        serde_json::from_value(program_json).expect("Project deserialization failed");

    project.replace_let_bindings();
    let mut project: crate::intermediate_representation::Project = project.into();
    let mut all_logs = project.normalize();
    let config: crate::analysis::pointer_inference::Config =
        serde_json::from_value(crate::utils::read_config_file("config.json")["Memory"].clone())
            .unwrap();
    let pi_analysis = crate::analysis::pointer_inference::run(&project, config, false);
    let (mut logs, cwes) = pi_analysis.collected_logs;
    all_logs.append(&mut logs);
    (
        cwes,
        all_logs
            .into_iter()
            .map(|log| format! {"{}", log})
            .collect(),
    )
}

caml!(rs_run_pointer_inference(program_jsonbuilder_val) {
    failwith_on_panic( || {
        let cwe_warnings_and_log = run_pointer_inference(program_jsonbuilder_val);
        let cwe_warnings_and_log_json = serde_json::to_string(&cwe_warnings_and_log).unwrap();
        let ocaml_string = ocaml::Str::from(&cwe_warnings_and_log_json as &str);
        ocaml::Value::from(ocaml_string)
    })
});

fn run_pointer_inference_and_print_debug(program_jsonbuilder_val: ocaml::Value) {
    let json_builder = unsafe { JsonBuilder::from_ocaml(&program_jsonbuilder_val) };
    let program_json = serde_json::Value::from(json_builder);
    let mut project: Project =
        serde_json::from_value(program_json).expect("Project deserialization failed");

    project.replace_let_bindings();
    let mut project: crate::intermediate_representation::Project = project.into();
    let _ = project.normalize();
    let config: crate::analysis::pointer_inference::Config =
        serde_json::from_value(crate::utils::read_config_file("config.json")["Memory"].clone())
            .unwrap();
    crate::analysis::pointer_inference::run(&project, config, true); // Note: This discard all CweWarnings and log messages.
}

caml!(rs_run_pointer_inference_and_print_debug(program_jsonbuilder_val) {
    failwith_on_panic( || {
        run_pointer_inference_and_print_debug(program_jsonbuilder_val);
        ocaml::Value::unit()
    })
});
