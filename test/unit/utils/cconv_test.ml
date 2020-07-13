open Bap.Std
open Core_kernel
open Cwe_checker_core

open Cconv

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None

let example_cconv = ref None

let example_arch = ref None


let test_callee_saved () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let arch = Option.value_exn !example_arch in
  let cconv = Option.value !example_arch  ~default: "" in
  match cconv with
  | "cdecl" | "fastcall" | "stdcall" | "ms" -> begin
      let register = Var.create "EBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "callee_saved_register" (is_callee_saved register project) in
      let register = Var.create "EAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "caller_saved_register" (is_callee_saved register project = false) in
      ()
  end
  | "" -> begin
    match arch with
    | "x86_64" -> begin
        let register = Var.create "RBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "R8" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "caller_saved_register" (is_callee_saved register project = false) in
        ()
      end
    | "mips" -> begin
        let register = Var.create "S0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "A0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project = false) in
        ()
    end
    | _ -> ()
  end
  | _ -> ()


let test_parameter_register () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let register = Var.create "RDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "return_register" (is_parameter_register register project) in
  let register = Var.create "R9" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "return_register" (is_parameter_register register project) in
  let register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "no_return_register" (is_parameter_register register project = false) in
  let register = Var.create "R14" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "no_return_register" (is_parameter_register register project = false) in
  ()


let test_return_register () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "return_register" (is_return_register register project) in
  let register = Var.create "R12" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let () = check "no_return_register" (is_return_register register project = false) in
  ()


let test_parse_dyn_syms () =
(* this test assumes, that the example project is the arrays_x64.out binary from the artificial samples. *)
  let project = Option.value_exn !example_project in
  let () = check "free_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "free") in
  let () = check "__libc_start_main_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "__libc_start_main") in
  let () = check "malloc_as_dyn_sym" (String.Set.mem (parse_dyn_syms project) "malloc") in
  let () = check "realloc_not_a_dyn_sym" (false = String.Set.mem (parse_dyn_syms project) "realloc") in
  ()

let tests = [
  "Callee saved register", `Quick, test_callee_saved;
  "Parameter register", `Quick, test_parameter_register;
  "Return register", `Quick, test_return_register;
  "Parse dynamic symbols", `Quick, test_parse_dyn_syms;
]
