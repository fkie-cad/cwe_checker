open Bap.Std
open Core_kernel
open Cwe_checker_core

include Self()

let main json_output project =

  let program = Project.program project in
  let tid_map = Address_translation.generate_tid_map program in
  Type_inference.print_type_info_tags project tid_map;
  if json_output then
    begin
      match Project.get project filename with
      | Some fname -> Log_utils.emit_cwe_warnings_json fname
      | None -> Log_utils.emit_cwe_warnings_json ""
    end
  else
    Log_utils.emit_cwe_warnings_native ()

module Cmdline = struct
  open Config
  let json_output = flag "json" ~doc:"Outputs the result as JSON."
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' ~deps:["cwe-checker-type-inference"] (main !!json_output))
  let () = manpage [`S "DESCRIPTION";
                    `P "This plugin prints the results of the type inference plugin."]
end
