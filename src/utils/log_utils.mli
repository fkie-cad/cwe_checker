(** This module implements the logging logic or cwe_checker.

    Each check may produce a CweWarning, which holds information regarding the current CWE hit.
    These CweWarnings are stored globally so that we can output at the very end. This may be
    necessary, for instance, when the output should be a JSON document.

    CWE checks can utilize the function cwe_warning_factory to create CweWarning objects and
    the function collect_cwe_warning to store them globally.

    At the moment, cwe_checker supports plain text and JSON output. The corresponding functions
    are emit_native and emit_json.

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
      source : string;
      destination : string;
      source_addr : string;
      destination_addr : string;
      path : string list;
      path_str : string;
    }
end

(**
This function turns on or off the logging of debug, error, and info messages to STDOUT / STDERR.
Use if you do not want to pollute your JSON output when outputting to STDOUT.
 *)
val turn_off_logging : unit -> unit

(**
Factory function to easily build an element of type CweWarning.t.
It takes the following input parameters:
- name: name of the CWE
- version: version of the cwe_check
- other: list of abritrary string elements (use as needed)
- addresses: list of relevant assembly addresses as strings
- tids: list of relevant TIDs as strings
- symbols: list of associated symbols as strings
- description: string description of the CWE
 *)
val cwe_warning_factory : string -> string -> ?other:string list list -> ?addresses:string list -> ?tids:string list -> ?symbols:string list -> string -> CweWarning.t

(**
Factory function to easily build an element of type CheckPath.t.
It takes the following input parameters:
- path: a list of strings of node on the path
- path_str: a string of the path between source and destination
- source: symbol of source
- source_addr: assembly address of source
- destination: symbol / address of destination
- destination_addr: assembly address of destination
 *)
val check_path_factory : ?path:string list -> ?path_str:string -> string -> string -> string -> string -> CheckPath.t

(**
Add one CweWarning.t element to an internal store. All elements are emited by calling one of the emit_* functions.
 *)
val collect_cwe_warning : CweWarning.t -> unit

(**
Add one CheckPath.t element to an internal store. All elements are emited by calling one of the emit_* functions.
 *)
val collect_check_path : CheckPath.t -> unit

(**
Returns the internal store of CweWarning.t elements as a list.
 *)
val get_cwe_warnings : unit -> CweWarning.t list

(**
Emits stored CweWarning.t and CheckPath.t elements as json.
target_path is the path of the current BAP project and out_path is the path a json output file.
 *)
val emit_json : string -> string -> unit

(**
Emits stored CweWarning.t and CheckPath.t elements.
target_path is the path of the current BAP project and out_path is the path an output file.
 *)
val emit_native : string -> unit

val debug : string -> unit
val error : string -> unit
val info : string -> unit
