(** This module implements a check for CWE-476: NULL Pointer Dereference.

    Functions like malloc() may return NULL values instead of pointers to indicate
    failed calls. If one tries to access memory through this return value without
    checking it for being NULL first, this can crash the program.

    See {: https://cwe.mitre.org/data/definitions/476.html} for a detailed description.

    {1 How the check works}

    We search for an execution path where a memory access using the return value of
    a symbol happens before the return value is checked through a conditional
    jump instruction.

    Note that the check relies on Bap-generated stubs to identify return registers of the
    checked functions. Therefore it only works for functions for which Bap generates
    these stubs.

    {2 Parameters configurable in config.json}

    - strict_call_policy=\{true, false\}: Determines behaviour on call and return instructions.
      If false, we assume that the callee, resp. the caller on a return instruction,
      checks all unchecked values still contained in the registers. If true, every
      unchecked value on a call or return instruction gets reported.
    - max_steps=<num>: Max number of steps for the dataflow fixpoint algorithm.

    {2 Symbols configurable in config.json}

    The symbols are the functions whose return values are assumed to be potential
    NULL pointers.

    {1 False Positives}

    - The check does not yet track values on the stack. Thus instances, where the
    return value gets written onto the stack before the check happens get incorrectly
    flagged. This happens a lot on unoptimized binaries but rarely on optimized ones.

    {1 False Negatives}

    - We do not check whether an access to a potential NULL pointer happens regardless
    of a prior check.
    - We do not check whether the conditional jump instruction checks specifically
    for the return value being NULL or something else
    - For functions with more than one return value we do not distinguish between
    the return values.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
