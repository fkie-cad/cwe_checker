(** This module implements a check for CWE-457: Use of Uninitialized Variable.

    Accessing variables on the stack or heap before their initialization can lead
    to unintended or undefined behaviour, which could be exploited by an attacker.

    See {: https://cwe.mitre.org/data/definitions/457.html} for a detailed description.

    {1 How the check works}

    The check uses the frame pointer to look for loads to addresses which do not
    have an associated store instruction.

    {1 False Positives}

    - The check is still very basic and can be easily get confused by loads/stores
    through different registers than the frame pointer.
    - Modern compilers often use only the stack pointer for stack access, freeing
    up the frame pointer as a general purpose register. This is not recognized by
    the check.

    {1 False Negatives}

    - Heap accesses are not examined by the check.
    - Memory accesses through different registers than the frame pointer are not
    examined by the check.
*)

val name: string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t ->  string list list -> string list -> unit
