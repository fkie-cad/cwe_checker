open Core_kernel
open Bap.Std
open Graphlib.Std
open Format
open Yojson.Basic.Util
open Cwe_checker_core

include Self()

type cwe_module = {
    cwe_func :  Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit;
    name : string;
    version : string;
    requires_pairs : bool;
    has_parameters : bool;
  }

let known_modules = [{cwe_func = Cwe_190.check_cwe; name = Cwe_190.name; version = Cwe_190.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_215.check_cwe; name = Cwe_215.name; version = Cwe_215.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_243.check_cwe; name = Cwe_243.name; version = Cwe_243.version; requires_pairs = true; has_parameters = false};
                     {cwe_func = Cwe_248.check_cwe; name = Cwe_248.name; version = Cwe_248.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_332.check_cwe; name = Cwe_332.name; version = Cwe_332.version; requires_pairs = true; has_parameters = false};
                     {cwe_func = Cwe_367.check_cwe; name = Cwe_367.name; version = Cwe_367.version; requires_pairs = true; has_parameters = false};
                     {cwe_func = Cwe_426.check_cwe; name = Cwe_426.name; version = Cwe_426.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_457.check_cwe; name = Cwe_457.name; version = Cwe_457.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_467.check_cwe; name = Cwe_467.name; version = Cwe_467.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_476.check_cwe; name = Cwe_476.name; version = Cwe_476.version; requires_pairs = false; has_parameters = true};
                     {cwe_func = Cwe_676.check_cwe; name = Cwe_676.name; version = Cwe_676.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_782.check_cwe; name = Cwe_782.name; version = Cwe_782.version; requires_pairs = false; has_parameters = false}]

let build_version_sexp () =
  List.map known_modules ~f:(fun cwe -> Format.sprintf "(\"%s\" \"%s\")" cwe.name cwe.version)
  |> String.concat ~sep:" "

let print_module_versions () =
  Log_utils.info
    "[cwe_checker] module_versions: (%s)"
    (build_version_sexp ())

let execute_cwe_module cwe json program project tid_address_map =
  let parameters = match cwe.has_parameters with
    | false -> []
    | true -> Json_utils.get_parameter_list_from_json json cwe.name in
   if cwe.requires_pairs = true then
     begin
       let symbol_pairs = Json_utils.get_symbol_lists_from_json json cwe.name in
       cwe.cwe_func program project tid_address_map symbol_pairs parameters
     end
   else
     begin
       let symbols = Json_utils.get_symbols_from_json json cwe.name in
       cwe.cwe_func program project tid_address_map [symbols] parameters
     end

let partial_run project config modules =
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in
  Log_utils.info "[cwe_checker] Just running the following analyses: %s." modules;
  List.iter (String.split modules ~on: ',') ~f:(fun cwe ->
    let cwe_mod = match List.find known_modules ~f:(fun x -> x.name = cwe) with
      | Some(module_) -> module_
      | None -> failwith "[CWE_CHECKER] Unknown CWE module" in
    let program = Project.program project in
    execute_cwe_module cwe_mod json program project tid_address_map
  )

let full_run project config =
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in
  begin
    List.iter known_modules ~f:(fun cwe -> execute_cwe_module cwe json program project tid_address_map)
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
      let config =
        if config = "" then
          (* try the standard installation path for the config file instead *)
          match Sys.getenv_opt "OPAM_SWITCH_PREFIX" with
          | Some(prefix) -> prefix ^ "/etc/cwe_checker/config.json"
          | None -> ""
        else
          config in
      if config = "" then
        Log_utils.error "[cwe_checker] No configuration file provided! Aborting..."
      else if Sys.file_exists config <> true then
        Log_utils.error "[cwe_checker] Configuration file not found. Aborting..."
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
  let partial_update = param string "partial" ~doc:"Comma separated list of modules to apply on binary, e.g. 'CWE332,CWE476,CWE782'"
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' ~deps:["callsites"] (main !!config !!module_versions !!partial_update))
  let () = manpage [
                          `S "DESCRIPTION";
                          `P
                            "This plugin checks various CWEs such as Insufficient Entropy in PRNG (CWE-332) or Use of Potentially Dangerous Function (CWE-676)"
                        ]
end
