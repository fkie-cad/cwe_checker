(** This module implements a check for CWE-560: Use of umask() with chmod-style Argument.

    The program uses the system call umask(2) with arguements for chmod(2). For instance,
    instead of a reasonable value like 0022 a value like 0666 is passed. This may result wrong
    read and/or write access to files and directories, which could be utilized to bypass
    protection mechanisms.

    See {: https://cwe.mitre.org/data/definitions/560.html} for a detailed description.

    {1 How the check works}

    This check looks for umask calls and checks if they have a reasonable value, i.e. smaller than
    a certain value, currently set to 1000 and greater than a reasonable value for umask, currently set to 100.

    {1 False Positives}

    - The current version considers all immediate values of an umask callsite's basic
    block. It does not check whether the value is an input to the call or not.

    {1 False Negatives}

    - If the input to umask is not defined in the basic block before the call, the
    check will not see it.
    - Calls where the input is not an immediate value but a variable are not examined.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit


(* functions made available for unit tests: *)
module Private : sig
  val is_chmod_style_arg : int -> bool
end
