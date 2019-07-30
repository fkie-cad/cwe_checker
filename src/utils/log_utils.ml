open Core_kernel

module CweWarning = struct
  type t = {
    name : string;
    version : string;
    addresses: string list;
    symbols: string list;
    other : string list list;
    description : string;
  } [@@deriving yojson]
end

module CweWarningResult = struct
  type t = {
      binary : string;
      time : float;
      warnings : CweWarning.t list;
    } [@@deriving yojson]
end

let cwe_warning_store = ref [||]

let no_logging = ref false

let turn_off_logging () = no_logging := true

let cwe_warning_factory name version ?(other = []) ?(addresses = []) ?(symbols = []) description =
  {
    CweWarning.name = name;
    CweWarning.version = version;
    CweWarning.description = description;
    CweWarning.other = other;
    CweWarning.addresses = addresses;
    CweWarning.symbols = symbols;
  }

let collect_cwe_warning warning = cwe_warning_store := Array.append !cwe_warning_store [|warning|]

let emit_cwe_warnings_json target_path out_path =
  let cwe_warning_result = {
      CweWarningResult.binary = target_path;
      CweWarningResult.time = Unix.time ();
      CweWarningResult.warnings = Array.to_list !cwe_warning_store
    } in
  let output = Yojson.Safe.pretty_to_string (CweWarningResult.to_yojson cwe_warning_result) in
  if out_path = "" then
    print_endline output
  else
    Out_channel.write_all out_path ~data:output

let emit_cwe_warnings_native out_path =
  let output_lines = Array.map !cwe_warning_store ~f:(fun (cwe_warning:CweWarning.t) ->
      sprintf "[%s] (%s) %s" cwe_warning.name cwe_warning.version cwe_warning.description) in
  if out_path = "" then
    Array.iter output_lines ~f:print_endline
  else
    Out_channel.write_lines out_path (Array.to_list output_lines)

let debug message = if !no_logging then () else print_endline ("DEBUG: " ^ message)

let info message = if !no_logging then () else print_endline ("INFO: " ^ message)

let error message = if !no_logging then () else print_endline ("ERROR: " ^ message)
