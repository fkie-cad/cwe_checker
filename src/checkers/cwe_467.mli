(** This module implements a check for CWE-467: Use of sizeof() on a Pointer Type.

    Functions like malloc and memmove take a size parameter of some data size as
    input. If accidentially the size of a pointer to the data instead of the size of
    the data itself gets passed to the function, this can have severe consequences.

    See {: https://cwe.mitre.org/data/definitions/467.html} for a detailed description.

    {1 How the check works}

    The check is quite basic: We check whether in the basic block before a call
    to a function listed in the symbols for CWE467 (configurable in in config.json)
    an immediate value that equals the size of a pointer (e.g. 4 bytes on x86) is
    referenced.

    {1 False Positives}

    - It is not checked whether the immediate value is actually an input to the call
    or not. However, this does not seem to produce false positives in practice.
    - The size value might be correct and not a bug.

    {1 False Negatives}

    - If the incorrect size value is generated before the basic block that contains
      the call, the check will not be able to find it.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
