(** This module implements a check for CWE-243 (Creation of chroot Jail Without Changing Working Directory).
According to http://www.unixwiz.net/techtips/chroot-practices.html, there are several ways to achieve the 
safe creation of a chroot jail, e.g. chdir -> chroot -> setuid. They are configurable in config.json.
See https://cwe.mitre.org/data/definitions/243.html for detailed description. *)
val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term ->
           Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list ->  unit
