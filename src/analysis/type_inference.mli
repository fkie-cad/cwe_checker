(* This file contains analysis passes for type recognition.

   It can annotate whether registers or values on the stack hold data or pointers
   to memory. For the latter the target memory location is also tracked if known.
   Pointers to the heap are tracked by tracking calls to malloc, calloc and realloc.
   This analysis does not check whether the return values of these calls are checked
   for NULL values (see cwe_476 for that). *)

open Bap.Std
open Core_kernel

(** The PointerTargetInfo contains knowledge about the offset and the alignment of
    a pointer into a memory area. Here the alignment is always considered relative
    offset zero of the target memory area. *)
module PointerTargetInfo : sig
  type t = {
    offset: (Bitvector.t, unit) Result.t Option.t;
    alignment: (int, unit) Result.t Option.t;
  } [@@deriving bin_io, compare, sexp]
end

(** The Register.t type. A register holds either arbitrary data or a pointer to some
    memory region. We do track possible targets of the pointer as follows:
    - heap objects: tid of corresponding call instruction to malloc, calloc, etc.
    - current stack frame: sub_tid of current function
    - some other stack frame: tid of corresponding call that left the stack frame.
      This way we can distinguish between current stack pointers and pointers to the
      stack frame of the same function coming from recursive calls. *)
module Register : sig
  type t =
    | Pointer of PointerTargetInfo.t Tid.Map.t
    | Data
  [@@deriving bin_io, compare, sexp]
end

(** The TypeInfo module. A TypeInfo.t structure holds a list of registers with known
    type information (see Register.t type) and known type information for values
    on the stack. *)
module TypeInfo : sig
  type reg_state = (Register.t, unit) Result.t Var.Map.t [@@deriving bin_io, compare, sexp]
  type t = {
    stack: Register.t Mem_region.t;
    reg: reg_state;
  } [@@deriving bin_io, compare, sexp]

  (* Pretty Printer. At the moment, the output is not pretty at all. *)
  val pp: Format.formatter -> t -> unit
end

(** A tag for TypeInfo.t, so that we can annotate basic blocks with known type information
using bap tags. *)
val type_info_tag: TypeInfo.t Value.tag

(** Computes TypeInfo for the given project. Adds tags to each block containing the
    TypeInfo at the start of the block. *)
val compute_pointer_register: Project.t -> Project.t

(** Print type info tags. TODO: If this should be used for more than debug purposes,
    then the output format should be refactored accordingly. *)
val print_type_info_tags: project:Project.t -> tid_map:word Tid.Map.t -> unit

(** Updates the type info for a single element (Phi/Def/Jmp) of a block. Input
    is the type info before execution of the element, output is the type info
    after execution of the element. sub_tid is the Tid of the current function
    which is internally used to mark which pointers point to the current stack frame.*)
val update_type_info: Blk.elt -> TypeInfo.t -> sub_tid:Tid.t -> project:Project.t -> TypeInfo.t

(* functions made available for unit tests: *)
module Private : sig
  val update_block_analysis: Blk.t -> TypeInfo.t -> sub_tid:Tid.t -> project:Project.t -> TypeInfo.t

  val function_start_state: Tid.t -> Project.t -> TypeInfo.t

  val compute_stack_offset: TypeInfo.t -> Exp.t -> sub_tid:Tid.t -> project:Project.t -> Bitvector.t Option.t

  val only_stack_pointer_and_flags: Tid.t -> Project.t -> TypeInfo.t

  val merge_type_infos: TypeInfo.t -> TypeInfo.t -> TypeInfo.t

  val type_info_equal: TypeInfo.t -> TypeInfo.t -> bool
end
