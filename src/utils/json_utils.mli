(** This module implements functionality related to parsing the JSON configuration file.

    It also contains FFI-functionality for generating serde_json objects on the Rust side
    which is used for converting complex Ocaml data structures to Rust data structures,
*)

open Core_kernel
open Bap.Std

val get_symbol_lists_from_json : Yojson.Basic.t -> string -> string list list
val get_symbols_from_json : Yojson.Basic.t -> string -> string list
val get_parameter_list_from_json : Yojson.Basic.t -> string -> string list

(** This module allows the creation of SerdeJson objects that can be deserialized
    to the corresponding data type in Rust.

    Note that this is not optimized for speed, extensive usage could lead to measureable slowdown.
*)
module SerdeJson : sig
  type t

  (** Build a Json Null object *)
  val build_null: unit -> t

  (** Build a Json boolean object *)
  val build_bool: Bool.t -> t

  (** Build a Json number object *)
  val build_number: int -> t

  (** Build a Json string object *)
  val build_string: String.t -> t

  (** Build a Json array object from a list of Json objects *)
  val build_array: t List.t -> t

  (** Build a Json object from a list of key-value-pairs *)
  val build_object: (String.t * t) List.t -> t

  (** Get the Json string corresponding to a Json object *)
  val to_string: t -> String.t

  val of_var_type: Bil.Types.typ -> t
  val of_var: Var.t -> t
  val of_cast_type: Bil.Types.cast -> t
  val of_binop_type: Bil.Types.binop -> t
  val of_unop_type: Bil.Types.unop -> t
  val of_endianness: Bitvector.endian -> t
  val of_bitvector: Bitvector.t -> t
  val of_exp: Exp.t -> t
  val of_tid: Tid.t -> t
  val of_def: Def.t -> t
  val of_jmp_label: Label.t -> t
  val of_call: Call.t -> t
  val of_jmp_kind: jmp_kind -> t
  val of_jmp: Jmp.t -> t
  val of_blk: Blk.t -> t
  val of_sub: Sub.t -> t
  val of_extern_symbol: Symbol_utils.extern_symbol -> t
  val of_program: Program.t -> Symbol_utils.extern_symbol List.t -> Tid.t List.t -> t
  val of_project: Project.t -> Symbol_utils.extern_symbol List.t -> Tid.t List.t -> t

end
