open Bap.Std
open Core_kernel
open Cwe_checker_core
open Cwe_checker_core.Cwe_476.Private

let check msg x = Alcotest.(check bool) msg true x

let example_project : Project.t Option.t ref = ref None

let call_handling_test () =
  let project = Option.value_exn !example_project in
  let state = State.empty in
  let mock_tid = Tid.create () in
  let mock_taint = Taint.add Taint.empty mock_tid in
  let mock_hits = ref Taint.empty in
  let rax_register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let rbx_register = Var.create "RBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let rdx_register = Var.create "RDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in

  let state = State.set_register state rax_register mock_taint in
  let _state = flag_unchecked_return_values state ~cwe_hits:mock_hits ~project in
  check "flag_RAX_return" (Bool.(=) false (Taint.is_empty !mock_hits));
  let state = State.empty in
  let state = State.set_register state rbx_register mock_taint in
  mock_hits := Taint.empty;
  let _state = flag_unchecked_return_values state ~cwe_hits:mock_hits ~project in
  check "dont_flag_RBX_return" (Taint.is_empty !mock_hits);

  let state = State.empty in
  mock_hits := Taint.empty;
  let state = State.set_register state rbx_register mock_taint in
  let _state = flag_register_taints state ~cwe_hits:mock_hits in
  check "flag_all_registers" (Bool.(=) false (Taint.is_empty !mock_hits));

  let state = State.empty in
  mock_hits := Taint.empty;
  let other_mock_taint = Taint.add Taint.empty (Tid.create ()) in
  let state = State.set_register state rdx_register mock_taint in
  let state = State.set_register state rbx_register other_mock_taint in
  let state = flag_parameter_register state ~cwe_hits:mock_hits ~project in
  check "flag_RDX_parameter" (Bool.(=) false (Taint.is_empty !mock_hits) && Option.is_none (State.find_register state rdx_register));
  check "dont_flag_RBX_parameter" (Option.is_some (State.find_register state rbx_register));

  let state = State.empty in
  mock_hits := Taint.empty;
  let state = State.set_register state rax_register mock_taint in
  let state = State.set_register state rbx_register other_mock_taint in
  let state = untaint_non_callee_saved_register state ~project in
  check "RAX_non_callee_saved" (Option.is_none (State.find_register state rax_register));
  check "RBX_callee_saved" (Option.is_some (State.find_register state rbx_register));
  ()

let state_test () =
  let project = Option.value_exn !example_project in
  let state = State.empty in
  let mock_tid = Tid.create () in
  let mock_taint = Taint.add Taint.empty mock_tid in
  let _mock_hits = ref Taint.empty in
  let rax_register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let rbx_register = Var.create "RBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let rdx_register = Var.create "RDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let state1 = State.set_register state rax_register mock_taint in
  let state2 = State.set_register state rbx_register mock_taint in
  let union_state = State.union state1 state2 in
  check "state_union_RAX" (Option.is_some (State.find_register union_state rax_register));
  check "state_union_RBX" (Option.is_some (State.find_register union_state rbx_register));
  check "state_union_not_RDX" (Option.is_none (State.find_register union_state rdx_register));
  ()

(* TODO: write checks for expression handling!! *)

let tests = [
  "Call Handling", `Quick, call_handling_test;
  "State Operations", `Quick, state_test;
]
