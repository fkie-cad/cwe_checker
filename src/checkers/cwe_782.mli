(** TODO
CWE-782 (Exposed IOCTL with Insufficient Access Control)
https://cwe.mitre.org/data/definitions/782.html *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
