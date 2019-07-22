open Core_kernel

module CweWarning = struct
  type t = {
    name : string;
    version : string;
    addresses: string list;
    symbols: string list;
    other : string list list;
    description : string;
  }
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

let emit_cwe_warnings_sexp () = ()

let emit_cwe_warnings_native () =
  Array.iter !cwe_warning_store ~f:(fun (cwe_warning:CweWarning.t) ->
      let line = (sprintf "[%s] (%s) " cwe_warning.name cwe_warning.version) ^ cwe_warning.description in
      print_endline line)

let debug message = print_endline ("DEBUG: " ^ message)

let info message = print_endline ("INFO: " ^ message)

let error message = print_endline ("ERROR: " ^ message)
