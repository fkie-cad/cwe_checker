(**
   This module contains the unit test infrastructure to coordiate
   each unit test in the cwe_checker/unit/ folder.

   To add an unit test and the corresponding test file,
   a few steps have to be performed before execution:

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
  ("tests", "Comma separated list defining which tests should be executed with the current test file. e.g. MemRegion,TypeInference,CWE476,...")
]

let unit_test_list = [
  "MemRegion", Mem_region_test.tests;
  "TypeInference", Type_inference_test.tests;
  "Cconv", Cconv_test.tests;
  "CWE476", Cwe_476_test.tests;
  "CWE560", Cwe_560_test.tests;
  "AddrTrans", Address_translation_test.tests;
  "SerdeJson", Serde_json_test.tests;
]


let check_for_cconv (project : Project.t) (arch : string) =
  match arch with
  | "i386" | "i686" -> Cconv_test.example_cconv := Project.get project Bap_abi.name
  | _ -> ()


let get_test_bin_format (project : Project.t) =
  let filename = match (Project.get project filename) with
    | Some(f) -> f
    | _ -> failwith "Test file has no file name" in
  match String.is_substring filename ~substring:"mingw32" with
  | true -> "pe"
  | false -> "elf"


let set_example_project (project : Project.t) (tests : string list) =
  let arch = Arch.to_string (Project.arch project) in
  List.iter tests ~f:(fun test ->
    match test with
    | "TypeInference" -> Type_inference_test.example_project := Some(project)
    | "Cconv" -> begin
        Cconv_test.example_project := Some(project);
        Cconv_test.example_arch := Some(arch);
        check_for_cconv project arch;
        Cconv_test.example_bin_format := Some(get_test_bin_format project)
    end
    | "CWE476" -> Cwe_476_test.example_project := Some(project)
    | "SerdeJson" -> Serde_json_test.example_project := Some(project)
    | _ -> ()
  )


let check_user_input (tests : string list) =
  let test_list = List.map unit_test_list ~f:(fun test -> match test with (name, _) -> name) in
  List.iter tests ~f:(fun test ->
    match Stdlib.List.mem test test_list with
    | true -> ()
    | false -> failwith (Printf.sprintf "Test %s is not a valid test." test)
  )


let filter_tests (tests : string list) : (string * unit Alcotest.test_case list) list =
  List.filter unit_test_list ~f:(fun (name, _) ->
     match Stdlib.List.mem name tests with
     | true -> true
     | false -> false
  )


let run_tests (params : String.t String.Map.t) (project : Project.t) =
  let test_param = match String.Map.find params "tests" with
  | Some(param) -> param
  | None -> failwith "No tests were provided to the unittest plugin." in
  let tests = (String.split test_param ~on: ',') in
  check_user_input tests;
  set_example_project project tests;
  Alcotest.run "Unit tests" ~argv:[|"DoNotComplainWhenRunAsABapPlugin";"--color=always";|] (filter_tests tests)


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
