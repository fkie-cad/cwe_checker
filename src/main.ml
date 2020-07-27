open Core_kernel
open Bap.Std
open Format

let version = "0.3-dev"

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
                     {cwe_func = Cwe_560.check_cwe; name = Cwe_560.name; version = Cwe_560.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_676.check_cwe; name = Cwe_676.name; version = Cwe_676.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Cwe_782.check_cwe; name = Cwe_782.name; version = Cwe_782.version; requires_pairs = false; has_parameters = false};
                     {cwe_func = Memory_cwes.check_cwe; name = Memory_cwes.name; version = Memory_cwes.version; requires_pairs = false; has_parameters = false}]


let cmdline_flags = [
  ("version", "Print the version number of the cwe_checker and quit");
  ("module-versions", "Prints out the version numbers of all known modules.");
  ("json", "Outputs the result as JSON.");
  ("no-logging", "Outputs no logging (info, error, warning). This does not pollute STDOUT when output json to it.");
  ("check-path", "Checks if there is a path from an input function to a CWE hit.");
]


let cmdline_params = [
  ("config", "Path to configuration file.");
  ("out", "Path to output file.");
  ("partial", "Comma separated list of modules to apply on binary, e.g. 'CWE332,CWE476,CWE782'");
  ("api", "C header file for additional subroutine information.")
]


let build_version_sexp () =
  List.map known_modules ~f:(fun cwe -> Format.sprintf "\"%s\": \"%s\"" cwe.name cwe.version)
  |> String.concat ~sep:", "


let print_module_versions () =
  Log_utils.info (sprintf "[cwe_checker] module_versions: {%s}" (build_version_sexp ()))


let print_version () =
  print_endline version


let print_help_message ((): unit) : unit =
  let flags = cmdline_flags in
  let params = cmdline_params in
  Printf.printf("Help:\n\nThe CWE checker is called using the following command structure:\n\n
  cwe_checker path/to/binary -[FLAG] -[PARAM=VALUE] ...\n\nThe following flags and parameters are available:\n\nFLAGS:\n\n");
  List.iter ~f:(fun x -> Printf.printf "    -%s: %s\n" (fst x) (snd x)) flags;
  Printf.printf("\nPARAMETERS:\n\n");
  List.iter ~f:(fun x -> Printf.printf "    -%s: %s\n" (fst x) (snd x)) params


let execute_cwe_module (cwe : cwe_module) (json : Yojson.Basic.t) (project : Project.t) (program : program term) (tid_address_map : word Tid.Map.t) : unit =
  let parameters = match cwe.has_parameters with
    | false -> []
    | true -> Json_utils.get_parameter_list_from_json json cwe.name in
  if cwe.requires_pairs = true then
    let symbol_pairs = Json_utils.get_symbol_lists_from_json json cwe.name in
    cwe.cwe_func program project tid_address_map symbol_pairs parameters
  else
    let symbols = Json_utils.get_symbols_from_json json cwe.name in
    cwe.cwe_func program project tid_address_map [symbols] parameters


let check_valid_module_list (modules : string list) : unit =
  let known_module_names = List.map ~f:(fun x -> x.name) known_modules in
  match List.find modules ~f:(fun module_name -> not (Stdlib.List.mem module_name known_module_names) ) with
  | Some module_name ->
      failwith ("[cwe_checker] Unknown CWE module " ^ module_name ^ ". Known modules: " ^ String.concat (List.map ~f:(fun x -> x ^ " ") known_module_names));
  | None -> ()


let partial_run (json : Yojson.Basic.t) (project : Project.t) (program : program term) (tid_address_map : word Tid.Map.t) (modules : string list) : unit =
  let () = check_valid_module_list modules in
  Log_utils.info (sprintf "[cwe_checker] Just running the following analyses: %s." (String.concat (List.map ~f:(fun x -> x ^ " ") modules)));
  List.iter modules ~f:(fun cwe ->
    let cwe_mod = match List.find known_modules ~f:(fun x -> x.name = cwe) with
      | Some(module_) -> module_
      | None -> failwith "[cwe_checker] Unknown CWE module" in
    execute_cwe_module cwe_mod json project program tid_address_map
  )


let full_run (json : Yojson.Basic.t) (project : Project.t) (program : program term) (tid_address_map : word Tid.Map.t) : unit =
  List.iter known_modules ~f:(fun cwe ->
    if cwe.name <> "Memory" then (* TODO: Remove this when the memory check is more stable *)
      execute_cwe_module cwe json project program tid_address_map)


let build_output_path (path : string) : string =
  try
    match Sys.is_directory path with
    | false -> path
    | true  ->
        let path = match String.is_suffix path ~suffix:"/" with
          | true -> path
          | false -> path ^ "/" in
        let path = path ^ "out-" ^ string_of_float (Unix.time ()) in
        Log_utils.info (sprintf "Created: %s" path);
        path
  with
  | _ -> path  (* file does not exist. We generate a new file with this name. *)


let main (flags : Bool.t String.Map.t) (params : String.t String.Map.t) (project : Project.t) =
  let config = String.Map.find_exn params "config" in
  let module_versions = String.Map.find_exn flags "module-versions" in
  let partial_update = String.Map.find_exn params "partial" in
  let check_path = String.Map.find_exn flags "check-path" in
  let json_output = String.Map.find_exn flags "json" in
  let file_output = String.Map.find_exn params "out" in
  let no_logging = String.Map.find_exn flags "no-logging" in
  let print_version_flag = String.Map.find_exn flags "version" in

  if print_version_flag then
    print_version ()
  else
  if module_versions then
    print_module_versions ()
  else
    begin
      if no_logging then Log_utils.turn_off_logging ();

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
          let prog = Project.program project in
          let tid_address_map = Address_translation.generate_tid_map prog in
          let json = Yojson.Basic.from_file config in
          let () = match Symbol_utils.check_if_symbols_resolved project prog tid_address_map with
          | false -> Log_utils.error "BAP is not able to resolve external symbols."
          | true -> () in
          if partial_update = "" then
            full_run json project prog tid_address_map
          else
            partial_run json project prog tid_address_map (String.split partial_update ~on: ',');
          if check_path then
            begin
              let check_path_sources = Json_utils.get_symbols_from_json json "check_path" in
              let check_path_sinks = Log_utils.get_cwe_warnings () in
              Check_path.check_path prog tid_address_map check_path_sources check_path_sinks
            end;
          let file_output =
            if file_output <> "" then
              build_output_path file_output
            else
              file_output in
          if json_output then
            begin
              match Project.get project filename with
              | Some fname -> Log_utils.emit_json fname file_output
              | None -> Log_utils.emit_json "" file_output
            end
          else
            Log_utils.emit_native file_output
        end
    end
