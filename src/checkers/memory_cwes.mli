(** This module implements memory-related CWE checks.

    Right now the check detects cases of

    - {{: https://cwe.mitre.org/data/definitions/415.html} CWE 415: Double Free}
    - {{: https://cwe.mitre.org/data/definitions/416.html} CWE 416: Use After Free}

    {1 How the check works}

    Via Dataflow Analysis, the check tries to keep track of all memory objects and pointers
    known at specific points in the program.
    It also keeps track of the status of memory object, i.e. if they have been already freed.
    Access to an already freed object generates a CWE warning.
    In cases where the analysis cannot reliably determine whether accessed memory has been freed or not,
    a CWE warning may (or may not) be issued to the user based on the likelihood of it being a false positive.

    Note that the check is still experimental.
    Bugs may occur and the rate of false positive and false negative warnings is not yet known.
*)


val name: string
val version: string


val check_cwe: Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
