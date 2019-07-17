(** This module implements a check for CWE-248: Uncaught Exception.

    An uncaught exception may lead to a crash and subsequentially to other unintended behavior.

    See {: https://cwe.mitre.org/data/definitions/248.html} for a detailed description.

    {1 How the check works}

    We search for exception throws that are reachable in the callgraph without
    touching a function that contains a catch block. We do not check whether a catch block
    can actually catch the thrown exceptions, thus we generate some false negatives.

    {1 False Positives}

    - There is no check whether a specific exception throw can be triggered or not

    {1 False Negatives}

    - An exception that gets catched through one execution path but would not get
    catched through a different execution path will not get flagged.
    - It is not checked whether the catch block can actually catch a thrown exception
    or not. A catch block may only be able to catch exceptions of a specific type.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
