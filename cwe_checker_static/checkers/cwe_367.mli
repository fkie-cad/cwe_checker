(** TODO
CWE-367 (Time-of-check Time-of-use (TOCTOU) Race Condition)
https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use
*)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
