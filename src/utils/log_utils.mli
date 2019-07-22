module CweWarning : sig
  type t = {
  name : string;
  version : string;
  addresses: string list;
  symbols: string list;
  other : string list list;
  description : string;
}
end

val cwe_warning_factory : string -> string -> ?other:string list list -> ?addresses:string list -> ?symbols:string list -> string -> CweWarning.t
val collect_cwe_warning : CweWarning.t -> unit
val emit_cwe_warnings_sexp : unit -> unit
val emit_cwe_warnings_native : unit -> unit
val debug : string -> unit
val error : string -> unit
val info : string -> unit
