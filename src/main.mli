(** This module defines the main driving function for the cwe_checker plugin in BAP.
*)

open Core_kernel
open Bap.Std

type cwe_module = {
  cwe_func :  Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit;
  name : string;
  version : string;
  requires_pairs : bool;
  has_parameters : bool;
}

val version: String.t

(** prints the version number *)
val print_version: unit -> unit

val known_modules: cwe_module List.t

val cmdline_flags: (String.t * String.t) List.t

val cmdline_params: (String.t * String.t) List.t

val print_module_versions: unit -> unit

val check_valid_module_list: string list -> unit

(** prints the help message *)
val print_help_message: unit -> unit

(** Executes one CWE module *)
val execute_cwe_module: cwe_module -> Yojson.Basic.t -> Bap.Std.project -> Bap.Std.program Bap.Std.term -> Bap.Std.word Bap.Std.Tid.Map.t -> unit

(** Only runs checks on CWE module specified by user. *)
val partial_run: Yojson.Basic.t -> Bap.Std.project -> Bap.Std.program Bap.Std.term -> Bap.Std.word Bap.Std.Tid.Map.t -> string list -> unit

(** Runs checks on all supported CWE modules. *)
val full_run: Yojson.Basic.t -> Bap.Std.project -> Bap.Std.program Bap.Std.term -> Bap.Std.word Bap.Std.Tid.Map.t -> unit


val build_output_path: string -> string

(** The main function drives the execution of the cwe_checker plugin in BAP.
    The command line arguments are passed as maps from their name to to their values
    (Bool.t for flags, String.t for other arguments) to this function.
*)
val main: Bool.t String.Map.t -> String.t String.Map.t -> Project.t -> unit
