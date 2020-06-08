open Bap.Std
open Core_kernel
open Cwe_checker_core

open Address_translation


let check msg x = Alcotest.(check bool) msg true x


let test_translate_tid_to_assembler_address_string () =
  let tid_map = Tid.Map.empty in
  let tid_1 = Tid.create () in
  let tid_2 = Tid.create () in
  let tid_map = Map.add_exn tid_map ~key:tid_1 ~data:(Addr.of_bool true) in
  let () = check "TID not correctly mapped to address" (translate_tid_to_assembler_address_string tid_1 tid_map = "1:1u") in
  let () = check "TID not correctly mapped to address" (translate_tid_to_assembler_address_string tid_2 tid_map = "UNKNOWN") in
  ()


let test_generate_tid_map () =
  let program = Program.create () in
  let program = Term.set_attr program address (Addr.of_bool false) in

  let s = Sub.create () in
  let b = Blk.create () in
  let x = Var.create "x" (Bil.Imm 8) in
  let y = Var.create "y" (Bil.Imm 8) in
  let z = Var.create "z" (Bil.Imm 8) in
  let d_1 = Def.create x Bil.(var y + var z) in
  let b = Term.append def_t b d_1 in
  let b = Term.set_attr b address (Addr.of_bool true) in
  let s = Term.append blk_t s b in

  let program = Term.append sub_t program s in
  let tid_map = generate_tid_map program in

  let () = check "address not in vicinity" (translate_tid_to_assembler_address_string (Term.tid s) tid_map = "UNKNOWN") in
  let () = check "address not in vicinity" (translate_tid_to_assembler_address_string (Term.tid d_1) tid_map = "1:1u") in
  ()


let tests = [
  "Generate TID map", `Quick, test_generate_tid_map;
  "Translate TID to assembler address string", `Quick, test_translate_tid_to_assembler_address_string
]
