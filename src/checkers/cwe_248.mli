(** This module implements a check for CWE-248 (Uncaught Exception)
An uncaught exception may lead to a crash and subsequentially to other unintended behavior.
See https://cwe.mitre.org/data/definitions/248.html for detailed description. *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.word Bap.Std.Tid.Map.t -> unit
