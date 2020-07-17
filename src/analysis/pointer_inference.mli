(** This module manages the communication with the actual pointer inference analysis
    through the foreign function interface to Rust.
*)

open Bap.Std

(** Run the pointer inference analysis and log the returned CWE warnings and log messages. *)
val run: Project.t -> Bap.Std.word Bap.Std.Tid.Map.t -> unit

(** Run the pointer inference analysis and print the computed state of each basic block
    (at the start and at the end of the basic block respectively)
    as json to stdout.
    Does not print log messages or CWE warnings.
    The output is meant for debugging purposes.
*)
val run_and_print_debug: Project.t -> Bap.Std.word Bap.Std.Tid.Map.t -> unit
