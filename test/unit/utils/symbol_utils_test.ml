open Core_kernel
open Cwe_checker_core
open Bap.Std

open Symbol_utils

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None


let test_check_if_symbols_resolved () =
  let project = Option.value_exn !example_project in
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let () = check "no_symbols" (Bool.(=) (check_if_symbols_resolved project program tid_address_map) false) in
  ()


let tests = [
  "Check if Symbols Resolved", `Quick, test_check_if_symbols_resolved;
]
