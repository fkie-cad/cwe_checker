(** This module implements a check for CWE-467 (Use of sizeof() on a Pointer Type).
In a nutshell, it before a function call to symbols like malloc and memmove, which
take a size parameter and a pointer to data as input, if not accidentally the size
of the pointer instead of the data is passed. This can have severe consequences.
The check is quite basic: it checks if before the call an immediate value that 
equals the size of a pointer (e.g. 4 bytes on x86) is referenced (e.g. pushed
onto the stack).The symbols are configurable in config.json.
See https://cwe.mitre.org/data/definitions/467.html for detailed description. *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term ->
           Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list ->  unit
