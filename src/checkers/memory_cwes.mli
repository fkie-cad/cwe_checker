(** This module implements memory-related CWE checks.

    Right now the check detects cases of

    - CWE 415: Double Free
    - CWE 416: Use After Free

    The check is still experimental.
    Bugs may occur and the rate of false positives is not known yet.
*)


val name: string
val version: string


(** Run the pointer analysis and report found memory CWEs *)
val check_cwe: Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
