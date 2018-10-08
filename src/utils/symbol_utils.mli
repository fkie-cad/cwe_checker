(** This module implements functionality to work with symbols (e.g. malloc).*)

type concrete_call = {
  call_site : Bap.Std.tid;
  symbol_address : Bap.Std.tid;
  name : string;
}

(** This type represents a symbol like malloc or memcpy. *)
type symbol = { address : Bap.Std.tid option; name : string; }

(** Finds a symbol string in a program and returns its IR address (tid). *)
val find_symbol : Bap.Std.program Bap.Std.term -> string -> Bap.Std.tid option

(** builds a list of symbols from a list of strings for a given program 
   TODO: maybe another data structure like a hashmap would be better. *)
val build_symbols : string list -> Bap.Std.program Bap.Std.term -> symbol list

(** Gets a symbol from a symbol list *)
val get_symbol : Bap.Std.tid -> symbol list -> symbol option

(** Given a JMP and symbol list, it returns its name as string.
   Use only if you are sure that the JMP calls a symbol. *)
val get_symbol_name_from_jmp : Bap.Std.Jmp.t -> symbol list -> string

(** Checks if a subfunction calls a symbol. *)
val sub_calls_symbol: Bap.Std.program Bap.Std.term -> Bap.Std.sub Bap.Std.term -> string -> bool

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
