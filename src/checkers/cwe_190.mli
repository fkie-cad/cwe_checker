(** This module implements a check for CWE-190: Integer overflow or wraparound.

    An integer overflow can lead to undefined behaviour and is especially dangerous
    in conjunction with memory management functions.

    See {: https://cwe.mitre.org/data/definitions/190.html} for a detailed description.

    {1 How the check works}

    For each call to a function from the CWE190 symbol list we check whether the
    basic block directly before the call contains a multiplication instruction.
    If one is found, the call gets flagged as a CWE hit, as there is no overflow
    check corresponding to the multiplication befor the call. The default CWE190
    symbol list contains the memory allocation functions {i malloc}, {i xmalloc},
    {i calloc} and {i realloc}. The list is configurable in config.json.

    {1 False Positives}

    - There is no check whether the result of the multiplication is actually used
      as input to the function call. However, this does not seem to generate a lot
      of false positives in practice.
    - There is no value set analysis in place to determine whether an overflow is
      possible or not at the specific instruction.

    {1 False Negatives}

    - All integer overflows not in a basic block right before a call to a function
    from the CWE190 symbol list.
    - All integer overflows caused by addition or subtraction.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
