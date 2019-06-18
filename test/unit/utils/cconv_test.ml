open Bap.Std
open Core_kernel
open Cwe_checker_core

open Cconv

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None

let test_callee_saved () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let register = Var.create "RBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "callee_saved_register" (is_callee_saved register project) in
  let register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "caller_saved_register" (is_callee_saved register project = false) in
  ()

let test_parse_dyn_syms () =
(* this test assumes, that the example project is the arrays_x64.out binary from the artificial samples. *)
  let project = Option.value_exn !example_project in
  let () = check "free_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "free") in
  let () = check "__libc_start_main_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "__libc_start_main") in
  let () = check "malloc_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "malloc") in
  let () = check "__cxa_finalize_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "__cxa_finalize") in
  let () = check "dyn_sym_count" (String.Set.count (parse_dyn_syms project) ~f:(fun _elem -> true) = 4) in
  ()

let tests = [
  "Callee saved register", `Quick, test_callee_saved;
  "Parse dynamic symbols", `Quick, test_parse_dyn_syms;
]
