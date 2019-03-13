open Bap.Std
open Core_kernel.Std
open Cwe_checker

let () = Alcotest.run "Unit tests" [
    "Mem_region_tests", Mem_region_test.mem_region_tests;
  ]
