(** This module implements a check for CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition.

    Time-of-check Time-of-use race conditions happen when a property of a resource
    (e.g. access rights of a file) get checked before the resource is accessed, leaving
    a short time window for an attacker to change the entity and thus invalidating
    the check before the access.

    See {: https://cwe.mitre.org/data/definitions/367.html} for a detailed description.

    {1 How the check works}

    For pairs of (check-call, use-call), configurable in config.json, we check whether
    a function may call the check-call before the use-call.

    {1 False Positives}

    - The check-call and the use-call may access different, unrelated resources
    (e. g. different files).

    {1 False Negatives}

    - If the check-call and the use-call happen in different functions it will not
      be found by the check.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
