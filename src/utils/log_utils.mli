module CweWarning : sig
  type t = {
  name : string;
  version : string;
  description : string;
}
end

val collect_cwe_warning : CweWarning.t -> unit
val emit_cwe_warnings_sexp : unit -> unit 
val debug : string -> unit
val error : string -> unit
