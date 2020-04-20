(** This module implements functionality to work with symbols (e.g. malloc).*)

open Core_kernel

type concrete_call = {
  call_site : Bap.Std.tid
  ; symbol_address : Bap.Std.tid
  ; name : string;
}

(** This type represents a symbol like malloc or memcpy. *)
type symbol = {
  address : Bap.Std.tid option
  ; name : string;
}

(** This type represents an external symbol. *)
type extern_symbol = {
  tid : Bap.Std.tid
  ; start_address : Bap.Std.Addr.t
  ; end_address : Bap.Std.Addr.t
  ; name : string
  ; cconv : string option
  ; args : (Bap.Std.Var.t * Bap.Std.Exp.t * Bap.Std.intent option) list;
}


(** Returns the calling convention for the whole project inferred by Bap. *)
val get_project_calling_convention : Bap.Std.Project.t -> string option

(** Returns the diassembly start and end address of an external symbol. *)
val find_symbol_addresses : Bap.Std.Project.t -> string list -> (string, Bap.Std.Addr.t list) Hashtbl.t

(** Checks whether the external symbols have already been built. If not, it calls the symbol builder. *)
val build_and_return_extern_symbols : Bap.Std.Project.t -> Bap.Std.program Bap.Std.term -> extern_symbol list

(** Builds a list of function symbols type from external function names given by objdump. *)
val build_extern_symbols : Bap.Std.Project.t -> Bap.Std.program Bap.Std.term -> unit

(** Adds an analysed internal symbol to the list of external symbols. *)
val add_extern_symbol : Bap.Std.Project.t -> Bap.Std.program Bap.Std.term -> string -> unit

(** Finds a symbol string in a program and returns its IR address (tid). *)
val find_symbol : Bap.Std.program Bap.Std.term -> string -> Bap.Std.tid option

(** builds a list of symbols from a list of strings for a given program
   TODO: maybe another data structure like a hashmap would be better. *)
val build_symbols : string list -> Bap.Std.program Bap.Std.term -> symbol list

(** Gets a symbol from a symbol list *)
val get_symbol : Bap.Std.tid -> symbol list -> symbol option

(** Gets a symbol from a string *)
val get_symbol_of_string : Bap.Std.program Bap.Std.term -> string -> symbol option

(** Given a JMP and symbol list, it returns its name as string.
   Use only if you are sure that the JMP calls a symbol. *)
val get_symbol_name_from_jmp : Bap.Std.Jmp.t -> symbol list -> string

(** Checks if a subfunction calls a symbol. *)
val sub_calls_symbol: Bap.Std.program Bap.Std.term -> Bap.Std.sub Bap.Std.term -> string -> bool

(** Checks if a callsite calls a symbol *)
val calls_callsite_symbol : Bap.Std.Jmp.t -> symbol -> bool

(** This function finds all (direct) calls in a program. It returns a list of tuples of (callsite, address).*)
val call_finder : (Bap.Std.tid * Bap.Std.tid) list Bap.Std.Term.visitor

(** Transform a call (e.g. found with call_finder) to concrete_call with the symbol resolved.*)
val transform_call_to_concrete_call :
  Bap.Std.tid * Bap.Std.tid -> symbol list -> concrete_call

(** Filters out all calls (callsite, target) that do not call to a known symbol.*)
val filter_calls_to_symbols :
  (Bap.Std.tid * Bap.Std.tid) list ->
  symbol list -> concrete_call list

(** Checks if a callsite is in a list of (interesting) concrete_calls *)
val is_interesting_callsite : Bap.Std.Jmp.t -> concrete_call list -> bool

(** TODO *)
val check_calls :
  concrete_call list ->
  Bap.Std.program Bap.Std.term ->
  'a ->
  'b ->
  'c ->
  ('a ->
   Bap.Std.program Bap.Std.term ->
   Bap.Std.sub Bap.Std.term ->
   Bap.Std.blk Bap.Std.term -> Bap.Std.jmp Bap.Std.term -> 'b -> 'c -> unit) ->
  unit

(** Returns a sequence of all (direct) callsites in a subfunction *)
val get_direct_callsites_of_sub :
  Bap.Std.sub Bap.Std.term -> Bap.Std.jmp Bap.Std.term Core_kernel.Sequence.t

(** Returns call count of symbol in function *)
val get_symbol_call_count_of_sub : string -> Bap.Std.Sub.t -> Bap.Std.Program.t -> int

(** Returns Some(target tid) if the block contains a direct call or None if it does not. *)
val extract_direct_call_tid_from_block : Bap.Std.blk Bap.Std.term -> Bap.Std.tid option

(** Returns a sequence of all entry points of the program.
    TODO: The _start entry point usually calls a libc-function which then calls the main function. Since right now only direct
    calls are tracked, our graph traversal may never find the main function. For now, we add it by hand to the entry points. *)
val get_program_entry_points : Bap.Std.program Bap.Std.term -> Bap.Std.sub Bap.Std.term List.t

(** Returns the stack register on the architecture of the given project. *)
val stack_register: Bap.Std.Project.t -> Bap.Std.Var.t

(** Returns a list of the known flag registers on the architecture of the given project.
    TODO: Right now it only returns flag registers that exist on all architectures.
    We should add known architecture dependend flag registers, too. *)
val flag_register_list: Bap.Std.Project.t -> Bap.Std.Var.t list


(** Returns the pointer size in bytes on the architecture of the given project. *)
val arch_pointer_size_in_bytes: Bap.Std.Project.t -> int
