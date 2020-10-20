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
  | `List ((`List cwe_warnings) :: (`List log_messages) :: []) ->
      List.iter cwe_warnings ~f:(fun warning -> Log_utils.collect_cwe_warning @@ Result.ok_or_failwith @@ Log_utils.CweWarning.of_yojson warning);
      List.iter log_messages ~f:(fun message ->
        match message with
        | `String message_string ->
            begin match String.lsplit2 message_string ~on:':' with
            | Some("ERROR", msg) -> Log_utils.error @@ String.strip msg
            | Some("DEBUG", msg) -> Log_utils.debug @@ String.strip msg
            | Some("INFO", msg) -> Log_utils.info @@ String.strip msg
            | _ -> failwith "Malformed log-message."
            end
        | _ -> failwith "Log-message is not a string."
      )
  | _ -> failwith "Log-message-json not as expected"

let run_and_print_debug (project: Project.t) (tid_map: Bap.Std.word Bap.Std.Tid.Map.t) : unit =
  let program = Project.program project in
  let entry_points = Symbol_utils.get_program_entry_points program in
  let entry_points = List.map entry_points ~f:(fun sub -> Term.tid sub) in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let project_serde = Serde_json.of_project project extern_symbols entry_points tid_map in
  rs_run_pointer_inference_and_print_debug project_serde
