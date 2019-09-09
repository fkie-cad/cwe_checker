(** This module implements the logging logic or cwe_checker.

    Each check may produce a CweWarning, which holds information regarding the current CWE hit.
    These CweWarnings are stored globally so that we can output at the very end. This may be
    necessary, for instance, when the output should be a JSON document.

    CWE checks can utilize the function cwe_warning_factory to create CweWarning objects and
    the function collect_cwe_warning to store them globally.

    At the moment, cwe_checker supports plain text and JSON output. The corresponding functions
    are emit_cwe_warnings_native and emit_cwe_warnings_json.

    In addition, there are several functions (debug, error, info) to notify the user of certain
    events. Note that these functions may pollute the output. 
 *)

module CweWarning : sig
  type t = {
  name : string;
  version : string;
  addresses: string list;
  tids: string list;
  symbols: string list;
  other : string list list;
  description : string;
}
end

module CheckPath : sig
  type t = {
      name : string;
    }
end

val cwe_warning_factory : string -> string -> ?other:string list list -> ?addresses:string list -> ?tids:string list -> ?symbols:string list -> string -> CweWarning.t
val collect_cwe_warning : CweWarning.t -> unit
val get_cwe_warnings : unit -> CweWarning.t list
val collect_check_path : CheckPath.t -> unit

val emit_cwe_warnings_json : string -> string -> unit
val emit_cwe_warnings_native : string -> unit

val debug : string -> unit
val error : string -> unit
val info : string -> unit
