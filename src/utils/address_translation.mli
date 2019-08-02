(** This module helps to translate between IR addresses and addresses found in the actual assembler code. 
At first, a mapping between the two addressing schemes has to be computed with the function generate_tid_map.
Call this function once at start up.Then, we can translate IR addresses (Bap.Std.tid) to addresses 
in assembler code (represented as string). *)

(** Generates a map that maps from TIDs to real addresses of the assembly code. *)
val generate_tid_map :
  Bap.Std.program Bap.Std.term -> Bap.Std.word Bap.Std.Tid.Map.t

(** Translates a TID to a real address of the assembly code.
   It requires a TID -> address mapping that can be generated with generate_tid_map. *)
val translate_tid_to_assembler_address_string :
  Bap.Std.tid -> Bap.Std.word Bap.Std.Tid.Map.t -> string
