open Core_kernel
open Cwe_checker_core
open Bap.Std
open Json_utils

let example_project = ref None

let check msg x = Alcotest.(check bool) msg true x

let test_serde () =
  let open Json_utils.SerdeJson in
  let serde = build_null () in
  let json = to_string serde in
  print_endline json;
  check "serde_null" (json = "null");
  let serde = build_bool true in
  let json = to_string serde in
  print_endline json;
  check "serde_bool" (json = "true");
  let serde = build_number 45 in
  let json = to_string serde in
  print_endline json;
  check "serde_number" (json = "45");
  let serde = build_string "hello" in
  let json = to_string serde in
  print_endline json;
  check "serde_string" (json = "\"hello\"");
  let serde = build_array [build_number 23; build_bool false] in
  let json = to_string serde in
  print_endline json;
  check "serde_array" (json = "[23,false]");
  let serde = build_object [("hello", build_number 23); ("world", build_bool false)] in
  let json = to_string serde in
  print_endline json;
  check "serde_object" (json = "{\"hello\":23,\"world\":false}")

let test_type_conversions () =
  let var_type = Bil.Types.Mem (`r64, `r8) in
  let serde = SerdeJson.of_var_type var_type in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Var_Type" (json = "{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}");
  let var = Var.create "RAX" var_type in
  let serde = SerdeJson.of_var var in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Var" (json = "{\"is_temp\":false,\"name\":\"RAX\",\"type_\":{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}}");
  let cast_type = Bil.Types.UNSIGNED in
  let serde = SerdeJson.of_cast_type cast_type in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Cast_Type" (json = "\"UNSIGNED\"");
  let unop = Bil.Types.NEG in
  let serde = SerdeJson.of_unop_type unop in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Unop_Type" (json = "\"NEG\"");
  let bitv = Bitvector.of_int ~width:8 234 in
  let serde = SerdeJson.of_bitvector bitv in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Bitvector" (json = "{\"digits\":[234],\"width\":[8]}");
  let exp = Bil.binop Bil.PLUS (Bil.int bitv) (Bil.int bitv) in
  let serde = SerdeJson.of_exp exp in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Expression" (json = "{\"BinOp\":{\"lhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}},\"op\":\"PLUS\",\"rhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}}}}");
  let tid = Tid.for_name "block" in
  let term = Blk.create ~tid () in
  let serde = SerdeJson.of_blk term in
  let json = SerdeJson.to_string serde in
  print_endline json;
  check "Block_term" (json = "{\"term\":{\"defs\":[],\"jmps\":[]},\"tid\":\"@block\"}")

let test_project_conversion () =
  let program = Project.program (Option.value_exn !example_project) in
  let serde = SerdeJson.of_program program in
  let _json = SerdeJson.to_string serde in
  check "Project" true

let tests = [
  "Serde Json Conversions", `Quick, test_serde;
  "Type Conversions", `Quick, test_type_conversions;
  "Project conversion", `Quick, test_project_conversion;
]
