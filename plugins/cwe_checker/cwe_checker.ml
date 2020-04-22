open Cwe_checker_core.Main
open Bap.Std
open Core_kernel

include Self()

let generate_bap_flags flags =
  List.map flags (fun (name, docstring) -> (name, Config.flag name ~doc:docstring))

let generate_bap_params params =
  List.map params (fun (name, docstring) -> (name, Config.param Config.string name ~doc:docstring))

let () =
  let cmdline_flags = generate_bap_flags cmdline_flags in
  let cmdline_params = generate_bap_params cmdline_params in
  let () = Config.when_ready (fun ({get=(!!)}) ->
    let flags: Bool.t String.Map.t = List.fold cmdline_flags ~init:String.Map.empty ~f:(fun flag_map (name, bap_flag) ->
      String.Map.set flag_map ~key:name ~data:(!!bap_flag)
    ) in
    let params: String.t String.Map.t = List.fold cmdline_params ~init:String.Map.empty ~f:(fun param_map (name, bap_param) ->
      String.Map.set param_map ~key:name ~data:(!!bap_param)
    ) in
    Project.register_pass' ~deps:["callsites"; "api"] (main flags params)
  ) in
  let () = Config.manpage [
    `S "DESCRIPTION";
    `P "This plugin checks various CWEs such as Insufficient Entropy in PRNG (CWE-332) or Use of Potentially Dangerous Function (CWE-676)"
  ] in
  ()
