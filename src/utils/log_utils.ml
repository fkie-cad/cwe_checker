open Core_kernel

module CweWarning = struct
  type t = {
    name : string;
    version : string;
    addresses: string list;
    tids: string list;
    symbols: string list;
    other : string list list;
    description : string;
  } [@@deriving yojson]
end

module CheckPath = struct
  type t = {
      source : string;
      destination : string;
      source_addr : string;
      destination_addr : string;
      path : string list;
      path_str : string;
    } [@@deriving yojson]
end

module CweCheckerResult = struct
  type t = {
      binary : string;
      time : float;
      warnings : CweWarning.t list;
      check_path : CheckPath.t list;
    } [@@deriving yojson]
end

let cwe_warning_store = ref []
let check_path_store = ref []

let no_logging = ref false

let turn_off_logging () = no_logging := true


let cwe_warning_factory name version ?(other = []) ?(addresses = []) ?(tids = []) ?(symbols = []) description =
  {
    CweWarning.name = name;
    CweWarning.version = version;
    CweWarning.description = description;
    CweWarning.other = other;
    CweWarning.addresses = addresses;
    CweWarning.tids = tids;
    CweWarning.symbols = symbols;
  }

let check_path_factory ?(path = []) ?(path_str = "") source source_addr destination destination_addr  =
  {
    CheckPath.source = source;
    CheckPath.source_addr = source_addr;
    CheckPath.destination = destination;
    CheckPath.destination_addr = destination_addr;
    CheckPath.path = path;
    CheckPath.path_str = path_str;
  }

let collect_cwe_warning warning = cwe_warning_store := !cwe_warning_store @ [warning]

let collect_check_path path = check_path_store := !check_path_store @ [path]

let get_cwe_warnings () = !cwe_warning_store

let emit_json target_path out_path =
  let cwe_warning_result = {
      CweCheckerResult.binary = target_path;
      CweCheckerResult.time = Caml_unix.time ();
      CweCheckerResult.warnings = !cwe_warning_store;
      CweCheckerResult.check_path = !check_path_store
    } in
  let output = Yojson.Safe.pretty_to_string (CweCheckerResult.to_yojson cwe_warning_result) in
  if  String.(=) out_path "" then
    print_endline output
  else
    Out_channel.write_all out_path ~data:output

let emit_native out_path =
  let output_check_path = List.map !check_path_store ~f:(fun (check_path:CheckPath.t) ->
                              sprintf "[CheckPath] %s(%s) -> %s via %s" check_path.source check_path.source_addr check_path.destination_addr check_path.path_str) in
  let output_warnings = List.map !cwe_warning_store ~f:(fun (cwe_warning:CweWarning.t) ->
                            sprintf "[%s] (%s) \n %s" cwe_warning.name cwe_warning.version cwe_warning.description) in
  let output_lines = output_warnings @ output_check_path in
  if String.(=) out_path "" then
    List.iter output_lines ~f:print_endline
  else
    Out_channel.write_lines out_path output_lines

let debug message = if !no_logging then () else print_endline ("DEBUG: " ^ message)

let info message = if !no_logging then () else print_endline ("INFO: " ^ message)

let error message = if !no_logging then () else print_endline ("ERROR: " ^ message)
