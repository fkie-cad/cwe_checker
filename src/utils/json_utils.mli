(* This module implements functionality related to parsing the JSON configuration file. *)

val get_symbol_lists_from_json : Yojson.Basic.t -> string -> string list list
val get_symbols_from_json : Yojson.Basic.t -> string -> string list
val get_parameter_list_from_json : Yojson.Basic.t -> string -> string list
