(** This module implements a check for CWE-782: Exposed IOCTL with Insufficient Access Control.

    See {: https://cwe.mitre.org/data/definitions/782.html} for a detailed description.

    {1 How the check works}

    Calls to ioctl() get flagged as CWE hits.

    {1 False Positives}

    - We cannot check whether the call contains sufficient access control.

    {1 False Negatives}

    - There are other ways to expose I/O control without access control.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
