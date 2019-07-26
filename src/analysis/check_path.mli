(**
This analyzer module checks if there exists a path from an input function (e.g. recv or scanf) to a location of a CWE hit. The existence of such a path is great news: we might trigger the CWE hit via user provided input. This helps analysts to further priotize the CWE hits.

The analysis prooves that there is a path that fulfills the following constraints:
- it starts at the location of an input function
- it ends at a CWE hit

This module is loosely based on the BAP tutorial (https://github.com/BinaryAnalysisPlatform/bap-tutorial/blob/master/src/path_check/path_check.ml). 
 *)

val name : string
val version : string

val check_path : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list -> Log_utils.CweWarning.t list -> unit
