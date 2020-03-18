(** This module implements a check for CWE-476: NULL Pointer Dereference.

    Functions like malloc() may return NULL values instead of pointers to indicate
    failed calls. If one tries to access memory through this return value without
    checking it for being NULL first, this can crash the program.

    See {: https://cwe.mitre.org/data/definitions/476.html} for a detailed description.

    {1 How the check works}

    Using dataflow analysis we search for an execution path where a memory access using the return value of
    a symbol happens before the return value is checked through a conditional jump instruction.

    Note that the check relies on Bap-generated stubs to identify return registers of the
    checked functions. Therefore it only works for functions for which Bap generates
    these stubs.

    {2 Parameters configurable in config.json}

    - strict_call_policy=\{true, false\}: Determines behaviour on call and return instructions.
      If false, we assume that the callee, resp. the caller on a return instruction,
      checks all unchecked values still contained in parameter registers. If true, every
      unchecked value on a call or return instruction gets reported.
    - strict_mem_policy=\{true, false\}:
      Determines behaviour on writing an unchecked return value to a memory region other than the stack.
      If true, these instances get reported.
      Depending on the coding style, this can lead to a lot false positives if return values are
      only checked after writing them to their target destination.
      If false, these instances do not get reported, which in turn can lead to false negatives.
    - max_steps=<num>: Max number of steps for the dataflow fixpoint algorithm.

    {2 Symbols configurable in config.json}

    The symbols are the functions whose return values are assumed to be potential
    NULL pointers.

    {1 False Positives}

    - If strict_mem_policy is set to true, writing a return value to memory other than the stack
    gets reported even if a NULL pointer check happens right afterwards.
    - The check has no knowledge about the actual number of parameters that an extern function call takes.
      This can lead to false positives if strict_call_policy is set to true.

    {1 False Negatives}

    - We do not check whether an access to a potential NULL pointer happens regardless
    of a prior check.
    - We do not check whether the conditional jump instruction checks specifically
    for the return value being NULL or something else
    - For functions with more than one return value we do not distinguish between
    the return values.
    - If strict_mem_policy is set to false, unchecked return values that are
    saved somewhere other than the stack may be missed.
    - The check has no knowledge about the actual number of parameters that an extern function call takes.
      This can lead to false negatives, especially if function parameters are passed on the stack.
*)

open Bap.Std
open Core_kernel

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit


(**/**)
(* Functions made public for unit tests *)
module Private : sig

  module Taint : module type of Tid.Set
  module State : sig
    type t
    val empty: t
    val set_register: t -> Var.t -> Taint.t -> t
    val find_register: t -> Var.t -> Taint.t Option.t
    val union: t -> t -> t
  end

  module StackInfo : sig
    type t
    val assemble_mock_info: Tid.t -> Project.t -> t
  end

  val flag_unchecked_return_values: State.t -> cwe_hits: Taint.t ref -> project: Project.t -> State.t
  val flag_register_taints: State.t -> cwe_hits: Taint.t ref -> State.t
  val flag_parameter_register: State.t -> cwe_hits: Taint.t ref -> project: Project.t -> State.t
  val untaint_non_callee_saved_register: State.t -> project: Project.t -> State.t
end
