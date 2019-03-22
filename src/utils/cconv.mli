open Bap.Std
open Core_kernel.Std

(** Returns whether a variable is callee saved according to the calling convention
    of the target architecture. Should only used for calls to functions outside
    of the program, not for calls between functions inside the program. *)
val is_callee_saved: Var.t -> Project.t -> bool


(** Returns a list of those function names that are extern symbols.
    TODO: Since we do not do name demangling here, check whether bap name demangling
    yields different function names for the symbols. *)
val parse_dyn_syms: Project.t -> string list
