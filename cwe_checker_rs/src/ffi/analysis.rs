use super::OcamlSendable;
use super::serde::JsonBuilder;
use crate::term::*;
use crate::utils::log::CweWarning;

use super::failwith_on_panic;


fn run_pointer_inference(program_jsonbuilder_val: ocaml::Value) -> (Vec<CweWarning>, Vec<String>) {
    let json_builder = unsafe { JsonBuilder::from_ocaml(&program_jsonbuilder_val) };
    let program_json = serde_json::Value::from(json_builder);
    let project: Project = serde_json::from_value(program_json).expect("Project deserialization failed");

    crate::analysis::pointer_inference::run(&project, false)
}

caml!(rs_run_pointer_inference(program_jsonbuilder_val) {
    return failwith_on_panic( || {
        let cwe_warnings_and_log = run_pointer_inference(program_jsonbuilder_val);
        let cwe_warnings_and_log_json = serde_json::to_string(&cwe_warnings_and_log).unwrap();
        let ocaml_string = ocaml::Str::from(&cwe_warnings_and_log_json as &str);
        ocaml::Value::from(ocaml_string)
    });
});

fn run_pointer_inference_and_print_debug(program_jsonbuilder_val: ocaml::Value) {
    let json_builder = unsafe { JsonBuilder::from_ocaml(&program_jsonbuilder_val) };
    let program_json = serde_json::Value::from(json_builder);
    let project: Project = serde_json::from_value(program_json).expect("Project deserialization failed");

    crate::analysis::pointer_inference::run(&project, true); // TODO: This discard all CweWarnings and log messages. Change that?
}

caml!(rs_run_pointer_inference_and_print_debug(program_jsonbuilder_val) {
    return failwith_on_panic( || {
        run_pointer_inference_and_print_debug(program_jsonbuilder_val);
        ocaml::Value::unit()
    });
});
