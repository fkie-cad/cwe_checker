open Bap.Std
open Core_kernel.Std
open Cwe_checker_core

let main project =
  Log_utils.set_log_level Log_utils.DEBUG;
  Log_utils.set_output stdout;
  Log_utils.color_on ();
  
  let program = Project.program project in
  let tid_map = Address_translation.generate_tid_map program in
  Type_inference.print_type_info_tags project tid_map

let () = Project.register_pass' main ~deps:["cwe-type-inference"]
