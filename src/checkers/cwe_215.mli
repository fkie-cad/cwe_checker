(**  This module checks if a binary contains sensitive debugging information that could be leveraged to
   get a better understanding of it in less time. This is basically CWE-215 (https://cwe.mitre.org/data/definitions/215.html *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list ->  unit
