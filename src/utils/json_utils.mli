(** This module implements functionality related to parsing the JSON configuration file.
*)


(** Returns pairs of symbols for a given CWE check. *)
val get_symbol_lists_from_json : Yojson.Basic.t -> string -> string list list


(** Returns symbols for a given CWE check. *)
val get_symbols_from_json : Yojson.Basic.t -> string -> string list


(** Returns parameters for a given CWE check. *)
val get_parameter_list_from_json : Yojson.Basic.t -> string -> string list


(** Returns an architecture's registers based on calling convention. *)
val get_arch_from_json : Yojson.Basic.t -> ?conv:string -> string -> Yojson.Basic.t


(** Returns json object containing either PE or ELF calling conventions for all architectures. *)
val get_bin_format_from_json : Yojson.Basic.t -> string -> Yojson.Basic.t


(** Returns registers for a given architecture and calling_convention specified by context. (e.g. callee saved, parameter etc.) *)
val get_registers_from_json : Yojson.Basic.t -> string -> string list


(** Returns a list of all architectures supported for a given binary format. (e.g. ELF) *)
val get_arch_list_from_json : Yojson.Basic.t -> string -> (string * Yojson.Basic.t) list
