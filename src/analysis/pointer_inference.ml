open Bap.Std
open Core_kernel



external rs_run_pointer_inference: Serde_json.t -> string = "rs_run_pointer_inference"
external rs_run_pointer_inference_and_print_debug: Serde_json.t -> unit = "rs_run_pointer_inference_and_print_debug"

type cwelist = Log_utils.CweWarning.t array [@@deriving yojson]

let run (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let entry_points = Symbol_utils.get_program_entry_points program in
  let entry_points = List.map entry_points ~f:(fun sub -> Term.tid sub) in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Serde_json.of_project project extern_symbols entry_points tid_map in
  let cwe_warnings_json = Yojson.Safe.from_string @@ rs_run_pointer_inference project_serde in
  match cwe_warnings_json with
  | `List cwe_warnings ->
      List.iter cwe_warnings ~f:(fun warning -> Log_utils.collect_cwe_warning @@ Result.ok_or_failwith @@ Log_utils.CweWarning.of_yojson warning)
  | _ -> failwith "Expected a list"

let run_and_print_debug (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let entry_points = Symbol_utils.get_program_entry_points program in
  let entry_points = List.map entry_points ~f:(fun sub -> Term.tid sub) in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Serde_json.of_project project extern_symbols entry_points tid_map in
  rs_run_pointer_inference_and_print_debug project_serde
