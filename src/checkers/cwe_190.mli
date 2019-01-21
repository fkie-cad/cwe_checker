(** TODO
CWE-190 (Integer Overflow or Wraparound)
https://cwe.mitre.org/data/definitions/190.html
*)
val name : string
val version : string  

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list ->  unit
