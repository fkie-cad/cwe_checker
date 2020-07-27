open Bap.Std
open Core_kernel
open Cwe_checker_core

include Self()

let main project =
  let program = Project.program project in
  let tid_map = Address_translation.generate_tid_map program in
  Pointer_inference.run_and_print_debug project tid_map

module Cmdline = struct
  open Config
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' main)
  let () = manpage [`S "DESCRIPTION";
                    `P "This plugin prints verbose debug information from the pointer inference analysis of the cwe_checker to stdout."]
end
