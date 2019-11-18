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

val known_modules: cwe_module List.t

val cmdline_flags: (String.t * String.t) List.t

val cmdline_params: (String.t * String.t) List.t

(** The main function drives the execution of the cwe_checker plugin in BAP.
    The command line arguments are passed as maps from their name to to their values
    (Bool.t for flags, String.t for other arguments) to this function.
*)
val main: Bool.t String.Map.t -> String.t String.Map.t -> Project.t -> unit
