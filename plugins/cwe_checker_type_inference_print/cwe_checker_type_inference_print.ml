open Bap.Std
open Core_kernel
open Cwe_checker_core

let main project =

  let program = Project.program project in
  let tid_map = Address_translation.generate_tid_map program in
  Type_inference.print_type_info_tags project tid_map;
  Log_utils.emit_cwe_warnings_native ()

let () = Project.register_pass' main ~deps:["cwe-checker-type-inference"]
