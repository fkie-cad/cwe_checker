use super::OcamlSendable;
use super::serde::JsonBuilder;
use crate::term::*;

use super::failwith_on_panic;


fn run_pointer_inference(program_jsonbuilder_val: ocaml::Value) {
    let json_builder = unsafe { JsonBuilder::from_ocaml(&program_jsonbuilder_val) };
    let program_json = serde_json::Value::from(json_builder);
    let program: Term<Program> = serde_json::from_value(program_json).expect("Program term deserialization failed");

    crate::analysis::pointer_inference::run(program);
}

caml!(rs_run_pointer_inference(program_jsonbuilder_val) {
    return failwith_on_panic( || {
        run_pointer_inference(program_jsonbuilder_val);
        ocaml::Value::unit()
    });
});
