open Bap.Std
open Core_kernel

external rs_run_pointer_inference: Serde_json.t -> unit = "rs_run_pointer_inference"
external rs_run_pointer_inference_and_print_debug: Serde_json.t -> unit = "rs_run_pointer_inference_and_print_debug"

let run (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let entry_points = Symbol_utils.get_program_entry_points program in
  let entry_points = List.map entry_points ~f:(fun sub -> Term.tid sub) in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Serde_json.of_project project extern_symbols entry_points in
  rs_run_pointer_inference project_serde

let run_and_print_debug (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let entry_points = Symbol_utils.get_program_entry_points program in
  let entry_points = List.map entry_points ~f:(fun sub -> Term.tid sub) in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Serde_json.of_project project extern_symbols entry_points in
  rs_run_pointer_inference_and_print_debug project_serde
