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

  (* Pretty Printer. *)
  val pp: Format.formatter -> t -> unit
end

(** Compute a map that sends a block tid to its state at the beginning of
    the block. *)
val compute_pointer_register: Project.t -> TypeInfo.t Tid.Map.t

(** Print blocks with an error register at the end of the block. TODO: only for
    testing, remove later. *)
val print_blocks_with_error_register: TypeInfo.t Tid.Map.t -> project:Project.t -> unit
