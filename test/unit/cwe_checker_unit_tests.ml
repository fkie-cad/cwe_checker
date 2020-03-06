open Bap.Std
open Core_kernel


let run_tests project =
  Type_inference_test.example_project := Some(project);
  Cconv_test.example_project := Some(project);
  Cwe_476_test.example_project := Some(project);
  Json_utils_test.example_project := Some(project);
  Alcotest.run "Unit tests" ~argv:[|"DoNotComplainWhenRunAsABapPlugin";"--color=always";|] [
    "Mem_region_tests", Mem_region_test.tests;
    "Type_inference_tests", Type_inference_test.tests;
    "Cconv_tests", Cconv_test.tests;
    "Json_utils_tests", Json_utils_test.tests;
    "CWE_476_tests", Cwe_476_test.tests;
    "CWE_560_tests", Cwe_560_test.tests;
     ]

let () =
  (* Check whether this file is run as an executable (via dune runtest) or
     as a bap plugin *)
  if Sys.argv.(0) = "bap" then
    (* The file was run as a bap plugin. *)
    Project.register_pass' run_tests
  else
    (* The file was run as a standalone executable. Use make to build and run the unit test plugin *)
    let () = try
        Sys.chdir (Sys.getenv "PWD" ^ "/test/unit")
      with _ -> (* In the docker image the environment variable PWD is not set *)
        Sys.chdir "/home/bap/cwe_checker/test/unit"
    in
    exit (Sys.command "make all")
