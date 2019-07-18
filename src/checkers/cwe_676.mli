(** This module implements a check for CWE-676: Use of Potentially Dangerous Function.

    Potentially dangerous functions like memcpy can lead to security issues like buffer
    overflows.

    See {: https://cwe.mitre.org/data/definitions/676.html} for a detailed description.

    {1 How the check works}

    Calls to dangerous functions are flagged. The list of functions that are considered
    dangerous can be configured in config.json. The default list is taken from
    {: https://github.com/01org/safestringlib/wiki/SDL-List-of-Banned-Functions}.

    {1 False Positives}

    None known

    {1 False Negatives}

    None known
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
