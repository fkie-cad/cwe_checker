open Core_kernel
open Cwe_checker_core

let check msg x = Alcotest.(check bool) msg true x

let test_is_chmod_style_arg_with_umask_arg () : unit =
  let res = Cwe_560.Private.is_chmod_style_arg 022 in
  check "empty" (res = false)

let test_is_chmod_style_arg_with_chmod_arg () : unit =
  let res = Cwe_560.Private.is_chmod_style_arg 666 in
  check "empty" (res = true)

let tests = [
  "Is chmod style argument with umask argument?", `Quick, test_is_chmod_style_arg_with_umask_arg;
  "Is chmod style argument with chmod argument?", `Quick, test_is_chmod_style_arg_with_chmod_arg;
]
