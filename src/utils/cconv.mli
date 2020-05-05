open Bap.Std
open Core_kernel

(** Returns a list of names of callee-saved registers for the standard calling convention of the given cpu architecture.
    Note that using this function may lead to errors if other calling conventions are used in a program. *)
val callee_saved_register_list: Project.t -> String.t List.t

(** Returns a list of names of parameter registers for the standard calling convention of the given cpu architecture.
    It is used as an approximation for extern functions whose parameters (and the number of parameters) are unknown.
    Note that using this function may lead to errors if other calling conventions are used in a program. *)
val get_parameter_register_list: Project.t -> String.t List.t

(** Returns whether a variable is callee saved according to the calling convention
    of the target architecture. Should only used for calls to functions outside
    of the program, not for calls between functions inside the program. *)
val is_callee_saved: Var.t -> Project.t -> Bool.t


(** Returns whether a variable may be used to pass parameters to a function.
    This depends on the calling convention of the target architecture and should only be used for extern function calls. *)
val is_parameter_register: Var.t -> Project.t -> Bool.t


(** Returns whether a variable may be used for return values of function calls.
    This depends on the calling convention of the target architecture and should only be used for extern function calls. *)
val is_return_register: Var.t -> Project.t -> Bool.t


(** Returns a list of those function names that are extern symbols.
    TODO: Since we do not do name demangling here, check whether bap name demangling
    yields different function names for the symbols. *)
val parse_dyn_syms: Project.t -> String.Set.t
