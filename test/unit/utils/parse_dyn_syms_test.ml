open Core_kernel
open Cwe_checker_core

open Symbol_utils

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None


let test_parse_dyn_syms () =
  (* this test assumes, that the example project is the arrays_x64.out binary from the artificial samples. *)
  let project = Option.value_exn !example_project in
  let () = check "free_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "free") in
  let () = check "__libc_start_main_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "__libc_start_main") in
  let () = check "malloc_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "malloc") in
  let () = check "realloc_not_a_dyn_sym" (false = String.Set.mem (parse_dyn_syms project) "realloc") in
  ()


let tests = [
  "Parse Dynamic Symbols", `Quick, test_parse_dyn_syms;
]
