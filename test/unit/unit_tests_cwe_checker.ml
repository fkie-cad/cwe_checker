(**
   This module contains the unit test infrastructure to coordiate
   each unit test in the cwe_checker/unit/ folder.

   To add an unit test and the corresponding test file,
   a few steps have to be performed before execution:

   - add the parameter for your unit test to the input_test_map in this module:
     the key contains the parameter name and the value is the name of the test

   - add the test list from your unit test to unit_test_list in this module

   - if your unit test utilises a example project, it has to be added to the set_example_project
     in this module.

   - add your corresponding test file to the testfiles folder in cwe_checker/unit/

   - call the unit test as bap plugin in the Makefile contained in the unit folder.
     The compiled test file will lie in the tmp folder.

   - lastly, run compile_testfile.sh in the specify_test_files_for_compilation contained in the unit folder
*)

open Bap.Std
open Core_kernel

include Self()

let cmdline_params = [
  ("partial", "Comma separated list defining which tests should be executed with the current test file. e.g. MemRegion,TypeInference,CWE476,...")
]


let input_test_map = Map.of_alist_exn (module String) [
  "MemRegion", "Mem_region_tests";
  "TypeInference", "Type_inference_tests";
  "CWE476", "CWE_476_tests";
  "CWE560", "CWE_560_tests";
  "AddrTrans", "Address_translation_tests";
  "Cconv", "Cconv_tests"
]

let unit_test_list = [
  "Mem_region_tests", Mem_region_test.tests;
  "Type_inference_tests", Type_inference_test.tests;
  "Cconv_tests", Cconv_test.tests;
  "CWE_476_tests", Cwe_476_test.tests;
  "CWE_560_tests", Cwe_560_test.tests;
  "Address_translation_tests", Address_translation_test.tests;
]


let set_example_project (project : Project.t) (tests : string list) =
  List.iter tests ~f:(fun test ->
    match test with
    | "Type_inference_tests" -> Type_inference_test.example_project := Some(project)
    | "Cconv_tests" -> Cconv_test.example_project := Some(project)
    | "CWE_476_tests" -> Cwe_476_test.example_project := Some(project)
    | _ -> ()
  )


let full_run (project : Project.t) =
  set_example_project project (List.map unit_test_list ~f:(fun test -> match test with (key, _) -> key));
  Alcotest.run "Unit tests" ~argv:[|"DoNotComplainWhenRunAsABapPlugin";"--color=always";|] unit_test_list

let partial_run (project : Project.t) (tests : string list) =
  set_example_project project tests;
  Alcotest.run "Unit tests" ~argv:[|"DoNotComplainWhenRunAsABapPlugin";"--color=always";|]
    (List.filter unit_test_list ~f:(fun (name, _) ->
       match Stdlib.List.mem name tests with
       | true -> true
       | false -> false
     ))


let check_and_translate_input (tests : string list) : string list =
  List.map tests ~f:(fun test ->
    match String.Map.find input_test_map test with
    | Some(tst) -> tst
    | None -> failwith (Printf.sprintf "Test: %s is invalid." test)
  )


let run_tests (params : String.t String.Map.t) (project : Project.t) =
  let tests = String.Map.find_exn params "partial" in
  match tests with
  | "" -> full_run project
  | _  -> begin
      let test_ids = check_and_translate_input (String.split tests ~on: ',') in
      partial_run project test_ids
    end


let generate_bap_params params =
  List.map params ~f:(fun (name, docstring) -> (name, Config.param Config.string name ~doc:docstring))


let () =
  (* Check whether this file is run as an executable (via dune runtest) or
     as a bap plugin *)
  if Sys.argv.(0) = "bap" then
    let cmdline_params = generate_bap_params cmdline_params in
    let () = Config.when_ready (fun ({get=(!!)}) ->
      let params: String.t String.Map.t = List.fold cmdline_params ~init:String.Map.empty ~f:(fun param_map (name, bap_param) ->
        String.Map.set param_map ~key:name ~data:(!!bap_param)) in
      Project.register_pass' (run_tests params)
    ) in
    ()
  else
    (* The file was run as a standalone executable. Use make to build and run the unit test plugin *)
    let () = try
        Sys.chdir (Sys.getenv "PWD" ^ "/test/unit")
      with _ -> (* In the docker image the environment variable PWD is not set *)
        Sys.chdir "/home/bap/cwe_checker/test/unit"
    in
    exit (Sys.command "make all")
