open Core_kernel
open Yojson.Basic.Util

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

let get_parameter_list_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "parameters"
  |> flatten
  |> List.map ~f:to_string
