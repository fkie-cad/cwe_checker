(** This module implements a check for CWE-215: Information Exposure Through Debug Information.

    Sensitive debugging information can be leveraged to get a better understanding
    of a binary in less time.

    See {: https://cwe.mitre.org/data/definitions/215.html} for a detailed description.

    {1 How the check works}

    The binary is checked for debug strings using readelf.

    {1 False Positives}

    None known.

    {1 False Negatives}

    - There may be other debug information not found by readelf.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list ->  unit
