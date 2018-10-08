(** This module checks for CWE-426 (Untrusted Search Path) (https://cwe.mitre.org/data/definitions/426.html). Basically, the program searches
for critical resources on an untrusted search path that can be adjusted by an adversary. For example, see Nebula Level 1
(https://exploit-exercises.com/nebula/level01/). 

According to "man system" the following problems can arise:
"Do not use system() from a program with set-user-ID or set-group-ID privileges, because strange values for some environment variables might 
be used to subvert system integrity.  Use the exec(3) family of functions instead, but not execlp(3) or execvp(3).  system() will not, in 
fact, work properly from programs with set-user-ID or set-group-ID privileges on systems on which /bin/sh is bash version 2, since bash 2 
drops privileges on startup.  (Debian uses a modified bash which does not do this when invoked as sh.)"
*)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list -> unit
