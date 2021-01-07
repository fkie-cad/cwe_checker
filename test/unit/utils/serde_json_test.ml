open Core_kernel
open Cwe_checker_core
open Bap.Std

let example_project = ref None

let check msg x = Alcotest.(check bool) msg true x

let test_serde () =
  let open Serde_json in
  let serde = build_null () in
  let json = to_string serde in
  print_endline json;
  check "serde_null" (String.(=) json "null");
  let serde = build_bool true in
  let json = to_string serde in
  print_endline json;
  check "serde_bool" (String.(=) json "true");
  let serde = build_number 45 in
  let json = to_string serde in
  print_endline json;
  check "serde_number" (String.(=) json "45");
  let serde = build_string "hello" in
  let json = to_string serde in
  print_endline json;
  check "serde_string" (String.(=) json "\"hello\"");
  let serde = build_array [build_number 23; build_bool false] in
  let json = to_string serde in
  print_endline json;
  check "serde_array" (String.(=) json "[23,false]");
  let serde = build_object [("hello", build_number 23); ("world", build_bool false)] in
  let json = to_string serde in
  print_endline json;
  check "serde_object" (String.(=) json "{\"hello\":23,\"world\":false}")

let test_type_conversions () =
  let var_type = Bil.Types.Mem (`r64, `r8) in
  let serde = Serde_json.of_var_type var_type in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Var_Type" (String.(=) json "{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}");
  let var = Var.create "RAX" var_type in
  let serde = Serde_json.of_var var in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Var" (String.(=) json "{\"is_temp\":false,\"name\":\"RAX\",\"type_\":{\"Memory\":{\"addr_size\":64,\"elem_size\":8}}}");
  let cast_type = Bil.Types.UNSIGNED in
  let serde = Serde_json.of_cast_type cast_type in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Cast_Type" (String.(=) json "\"UNSIGNED\"");
  let unop = Bil.Types.NEG in
  let serde = Serde_json.of_unop_type unop in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Unop_Type" (String.(=) json "\"NEG\"");
  let bitv = Bitvector.of_int ~width:8 234 in
  let serde = Serde_json.of_bitvector bitv in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Bitvector" (String.(=) json "{\"digits\":[234],\"width\":[8]}");
  let exp = Bil.binop Bil.PLUS (Bil.int bitv) (Bil.int bitv) in
  let serde = Serde_json.of_exp exp in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Expression" (String.(=) json "{\"BinOp\":{\"lhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}},\"op\":\"PLUS\",\"rhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}}}}");
  let tid = Tid.for_name "block" in
  let term = Blk.create ~tid () in
  let tid_map = Tid.Map.empty in
  let serde = Serde_json.of_blk term tid_map in
  let json = Serde_json.to_string serde in
  print_endline json;
  check "Block_term" (String.(=) json "{\"term\":{\"defs\":[],\"jmps\":[]},\"tid\":{\"address\":\"UNKNOWN\",\"id\":\"@block\"}}";)

let test_project_conversion () =
  let project = Option.value_exn !example_project in
  let program = Project.program project in
  let tid_map = Address_translation.generate_tid_map program in
  let extern_symbols = Symbol_utils.build_and_return_extern_symbols project program tid_map in
  let entry_points = [] in
  let serde = Serde_json.of_program program extern_symbols entry_points tid_map in
  let _json = Serde_json.to_string serde in
  (* TODO: The unit test for pointer inference should be moved to another file *)
  Pointer_inference.run project tid_map;
  Log_utils.emit_json "bin" "";
  Log_utils.emit_native "";
  check "Project" true

let tests = [
  "Serde Json Conversions", `Quick, test_serde;
  "Type Conversions", `Quick, test_type_conversions;
  "Project conversion", `Quick, test_project_conversion;
]
