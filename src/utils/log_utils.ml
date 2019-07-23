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

let emit_cwe_warnings_json filename =
  let cwe_warning_result = {
      CweWarningResult.binary = filename;
      CweWarningResult.time = Unix.time ();
      CweWarningResult.warnings = Array.to_list !cwe_warning_store
    } in
  let output = Yojson.Safe.pretty_to_string (CweWarningResult.to_yojson cwe_warning_result) in
      print_endline output

let emit_cwe_warnings_native () =
  Array.iter !cwe_warning_store ~f:(fun (cwe_warning:CweWarning.t) ->
      let line = (sprintf "[%s] (%s) " cwe_warning.name cwe_warning.version) ^ cwe_warning.description in
      print_endline line)

let debug message = print_endline ("DEBUG: " ^ message)

let info message = print_endline ("INFO: " ^ message)

let error message = print_endline ("ERROR: " ^ message)
