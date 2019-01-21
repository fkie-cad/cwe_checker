(** This module implements a check for CWE-476 (NULL Pointer Dereference).
It checks if the result of a function that may return a NULL value is checked immediately
for NULL. The symbols are configurable in config.json.
See https://cwe.mitre.org/data/definitions/476.html for detailed description. *)
val name: string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list ->  unit
