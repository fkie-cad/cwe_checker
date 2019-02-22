(** This module implements a check for CWE-676 (Use of Potentially Dangerous Function)
Potentially dangerous functions like memcpy can lead to security issues like buffer overflows.
The functions are configurable in config.json.
See https://cwe.mitre.org/data/definitions/676.html for detailed description. *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
