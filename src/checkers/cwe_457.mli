(** This module implements a check for CWE-457 (Use of Uninitialized Variable).
TODO
See https://cwe.mitre.org/data/definitions/457.html for detailed description. *)
val name: string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> unit
