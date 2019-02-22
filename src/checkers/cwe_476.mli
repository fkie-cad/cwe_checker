(** This module implements a check for CWE-476 (NULL Pointer Dereference).
    It checks if the result of a function that may return a NULL value is checked
    for NULL before any memory gets accessed using the return values. The symbols
    are configurable in config.json. See https://cwe.mitre.org/data/definitions/476.html
    for detailed description.

    Parameters:
    - strict_call_policy={true, false}: Determines behaviour on call and return instructions.
      If false, we assume that the callee, resp. the caller on a return instruction,
      checks all unchecked values still contained in the registers. If true, every
      unchecked value on a call or return instruction gets reported.
    - max_steps=<num>: Max number of steps for the dataflow fixpoint algorithm.

    Notes: The check relies on Bap-generated stubs to identify return registers of the
    checked functions. Therefore it only works for functions for which Bap generates
    these stubs. *)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
