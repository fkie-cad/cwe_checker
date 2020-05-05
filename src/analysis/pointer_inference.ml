open Bap.Std

external rs_run_pointer_inference: Json_utils.SerdeJson.t -> unit = "rs_run_pointer_inference"

let run (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Json_utils.SerdeJson.of_project project extern_symbols in
  rs_run_pointer_inference project_serde
