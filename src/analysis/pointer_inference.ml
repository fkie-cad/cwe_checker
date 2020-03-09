open Bap.Std

external rs_run_pointer_inference: Json_utils.SerdeJson.t -> unit = "rs_run_pointer_inference"

let run (project: Project.t) : unit =
  let program = Project.program project in
  let program_serde = Json_utils.SerdeJson.of_program program in
  rs_run_pointer_inference program_serde
