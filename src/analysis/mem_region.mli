(** contains an abstract memory region data type where you can assign arbitrary data to locations
    inside the memory regions. A memory region has no fixed size, so it can be used
    for memory regions of variable size like arrays or stacks.

    TODO: Right now this data structure is unsuited for elements that get only partially loaded. *)

open Bap.Std
open Core_kernel

type 'a t [@@deriving bin_io, compare, sexp]


(** Get an empty memory region- *)
val empty: unit -> 'a t


(** Add an element to the memory region. If the element intersects existing elements,
    the non-overwritten part gets marked as Error *)
val add: 'a t -> 'a -> pos:Bitvector.t -> size:Bitvector.t -> 'a t

(** Mark the memory region between pos (included) and pos+size (excluded) as empty.
    If elements get partially removed, mark the non-removed parts as Error *)
val remove: 'a t -> pos:Bitvector.t -> size:Bitvector.t -> 'a t

(** Returns the element and its size at position pos or None, when there is no element at that position.
    If pos intersects an element but does not match its starting position, it returns Some(Error(())). *)
val get: 'a t -> Bitvector.t -> (('a * Bitvector.t), unit) Result.t Option.t

(** Merge two memory regions. Elements with the same position and size get merged using
    data_merge, other intersecting elements get marked as Error. Note that data_merge
    may return None (to remove the elements from the memory region) or Some(Error(_)) to
    mark the merged element as error. *)
val merge: 'a t -> 'a t -> data_merge:('a -> 'a -> ('a, 'b) result option) -> 'a t

(** Check whether two memory regions are equal. *)
val equal: 'a t -> 'a t -> data_equal:('a -> 'a -> bool) -> bool

(** Mark an area in the mem_region as containing errors. *)
val mark_error: 'a t -> pos:Bitvector.t -> size:Bitvector.t -> 'a t

(** Map the contained data to new values. *)
val map_data: 'a t -> f:('a -> 'b) -> 'b t

(** List the contained data (ignoring error values). *)
val list_data: 'a t -> 'a List.t

(** List the contained data (ignoring error values) together with their positions. *)
val list_data_pos: 'a t -> (Bitvector.t * 'a) List.t
