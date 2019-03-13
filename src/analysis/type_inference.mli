(* This file contains analysis passes for type recognition *)

open Bap.Std
open Core_kernel.Std


(** The register type. *)
module Register : sig
  type t =
    | Pointer
    | Data
end

(* TODO: Either rename it to something more useful or make it opaque. *)
module State : sig
  type reg_state = (Register.t, unit) result Map.Make(Var).t
  type t = {
    stack: Register.t Mem_region.t;
    stack_offset: (Bitvector.t, unit) result option;
    reg: reg_state;
  }
end

(** Compute a map that sends a block tid to its state at the beginning of
    the block. *)
val compute_pointer_register: Project.t -> State.t Tid.Map.t

(** Print blocks with an error register at the end of the block. TODO: only for
    testing, remove later. *)
val print_blocks_with_error_register: State.t Tid.Map.t -> project:Project.t -> unit
