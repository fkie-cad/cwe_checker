open Core_kernel.Std
open Bap.Std
open Graphlib.Std
open Format
open Yojson.Basic.Util

include Self()

type cwe_module = {
    cwe_func :  Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list ->  unit;
    name : string;
    version : string;
    requires_pairs : bool;
  }

let known_modules = [{cwe_func = Cwe_190.check_cwe; name = Cwe_190.name; version = Cwe_190.version; requires_pairs = false};
                     {cwe_func = Cwe_215.check_cwe; name = Cwe_215.name; version = Cwe_215.version; requires_pairs = false};
                     {cwe_func = Cwe_243.check_cwe; name = Cwe_243.name; version = Cwe_243.version; requires_pairs = true};
                     {cwe_func = Cwe_332.check_cwe; name = Cwe_332.name; version = Cwe_332.version; requires_pairs = true};
                     {cwe_func = Cwe_367.check_cwe; name = Cwe_367.name; version = Cwe_367.version; requires_pairs = true};
                     {cwe_func = Cwe_426.check_cwe; name = Cwe_426.name; version = Cwe_426.version; requires_pairs = false};
                     {cwe_func = Cwe_457.check_cwe; name = Cwe_457.name; version = Cwe_457.version; requires_pairs = false};
                     {cwe_func = Cwe_467.check_cwe; name = Cwe_467.name; version = Cwe_467.version; requires_pairs = false};
                     {cwe_func = Cwe_476.check_cwe; name = Cwe_476.name; version = Cwe_476.version; requires_pairs = false};
                     {cwe_func = Cwe_676.check_cwe; name = Cwe_676.name; version = Cwe_676.version; requires_pairs = false};
                     {cwe_func = Cwe_782.check_cwe; name = Cwe_782.name; version = Cwe_782.version; requires_pairs = false}]

let build_version_sexp () = 
  List.map known_modules ~f:(fun cwe -> Format.sprintf "(\"%s\" \"%s\")" cwe.name cwe.version)
  |> String.concat ~sep:" "
  
let print_module_versions () =
  Log_utils.info
    "[cwe_checker] module_versions: (%s)"
    (build_version_sexp ())

(** Extracts the symbols to check for from json document.
An example looks like this:
"CWE467": {
	"symbols": ["strncmp", "malloc",
		    "alloca", "_alloca", "strncat", "wcsncat",
		    "strncpy", "wcsncpy", "stpncpy", "wcpncpy",
		    "memcpy", "wmemcpy", "memmove", "wmemmove", "memcmp", "wmemcmp"],
	"_comment": "any function that takes something of type size_t could be a possible candidate."
    }, *)
let get_symbols_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "symbols"
  |> flatten
  |> List.map ~f:to_string

let get_symbol_lists_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "pairs"
  |> flatten
  |> List.map ~f:(fun l -> List.map (to_list l) ~f:to_string)

let partial_run project config modules =
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in 
  Log_utils.info "[cwe_checker] Just running a partial update of %s." modules
  
let full_run project config = 
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in 
  begin
    List.iter known_modules ~f:(fun cwe -> if cwe.requires_pairs = true then
                                             begin
                                               let symbol_pairs = get_symbol_lists_from_json json cwe.name in 
                                                cwe.cwe_func program project tid_address_map symbol_pairs
                                             end
                                           else
                                             begin
                                               let symbols = get_symbols_from_json json cwe.name in 
                                               cwe.cwe_func program project tid_address_map [symbols]
                                             end)
  end
  
let main config module_versions partial_update project =
  Log_utils.set_log_level Log_utils.DEBUG;
  Log_utils.set_output stdout;
  Log_utils.color_on ();

  if module_versions then
    begin
      print_module_versions ()
    end
  else
    begin
      if config = "" then
        Log_utils.error "[cwe_checker] No configuration file provided! Aborting..."
      else
        begin
          if partial_update = "" then
            full_run project config
          else
            partial_run project config partial_update
        end
    end
  
module Cmdline = struct
  open Config
  let config = param string "config" ~doc:"Path to configuration file."
  let module_versions = param bool "module_versions" ~doc:"Prints out the version numbers of all known modules."
  let partial_update = param string "partial" ~doc:"Comma separated list of modules to apply on binary."
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' ~deps:["callsites"] (main !!config !!module_versions !!partial_update))
  let () = manpage [
                          `S "DESCRIPTION";
                          `P
                            "This plugin checks various CWEs such as Insufficient Entropy in PRNG (CWE-332) or Use of Potentially Dangerous Function (CWE-676)"
                        ]
end
