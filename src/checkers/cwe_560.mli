(** The program uses the system call umask(2) with arguements for chmod(2). For instance,
instead of a reasonable value like 0022 a value like 0666 is passed. This may result wrong
read and/or write access to files and directories, which could be utilized to bypass
protection mechanisms.

This check looks for umask calls and checks if they have a reasonable value, i.e. smaller than
a certain value.

CWE-560 (Use of umask() with chmod-style Argument)
https://cwe.mitre.org/data/definitions/560.html
*)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
