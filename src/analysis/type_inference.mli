(* This file contains analysis passes for type recognition *)

open Bap.Std
open Core_kernel.Std


(** The register type. *)
module Register : sig
  type t =
    | Pointer
    | Data
  [@@deriving bin_io, compare, sexp]

end

(* TODO: Either rename it to something more useful or make it opaque. *)
module TypeInfo : sig
  type reg_state = (Register.t, unit) Result.t Var.Map.t [@@deriving bin_io, compare, sexp]
  type t = {
    stack: Register.t Mem_region.t;
    stack_offset: (Bitvector.t, unit) Result.t Option.t;
    reg: reg_state;
  } [@@deriving bin_io, compare, sexp]

  (* Pretty Printer. At the moment, the output is not pretty at all. *)
  val pp: Format.formatter -> t -> unit
end

val type_info_tag: TypeInfo.t Value.tag

(** Computes TypeInfo for the given project. Adds tags to each block containing the
    TypeInfo at the start of the block. *)
val compute_pointer_register: Project.t -> Project.t

(** Print blocks with an error register at the end of the block. TODO: only for
    testing, remove later. *)
val print_blocks_with_error_register: project:Project.t -> unit

(** Updates the type info for a single element (Phi/Def/Jmp) of a block. Input
    is the type info before execution of the element, output is the type info
    after execution of the element. *)
val update_type_info: Blk.elt -> TypeInfo.t -> project:Project.t -> TypeInfo.t

(* functions made public for unit tests: *)
val update_block_analysis: Blk.t -> TypeInfo.t -> project:Project.t -> TypeInfo.t
