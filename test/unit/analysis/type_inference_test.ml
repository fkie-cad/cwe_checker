open Bap.Std
open Core_kernel.Std

open Type_inference

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None

(* TODO: As soon as more pointers than stack pointer are tracked, add more tests! *)

let create_block_from_defs def_list =
  let block = Blk.Builder.create () in
  let () = List.iter def_list ~f:(fun def -> Blk.Builder.add_def block def) in
  Blk.Builder.result block

let start_state stack_register project =
  let bv x = Bitvector.of_int x ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8) in
  let start_reg = Var.Map.empty in
  let start_reg = Map.add start_reg ~key:stack_register ~data:(Ok(Register.Pointer)) in
  { TypeInfo.stack = Mem_region.empty ();
    TypeInfo.stack_offset = Some (Ok(bv 0));
    TypeInfo.reg = start_reg;
  }

let test_update_stack_offset () =
  let project = Option.value_exn !example_project in
  let bv x = Bitvector.of_int x ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8) in
  let stack_register = Symbol_utils.stack_register project in
  let fn_start_state = start_state stack_register project in
  let def1 = Def.create stack_register (Bil.binop Bil.plus (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create stack_register (Bil.binop Bil.minus (Bil.var stack_register) (Bil.int (bv 16))) in
  let block = create_block_from_defs [def1; def2] in
  let state = update_block_analysis block fn_start_state project in
  let () = check "update_stack_offset" (state.TypeInfo.stack_offset = Some(Ok(Bitvector.unsigned (bv (-8))))) in
  ()

let test_update_reg () =
  let project = Option.value_exn !example_project in
  let bv x = Bitvector.of_int x ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8) in
  let stack_register = Symbol_utils.stack_register project in
  let fn_start_state = start_state stack_register project in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let register2 = Var.create "Register2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.binop Bil.AND (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create register2 (Bil.binop Bil.XOR (Bil.var register1) (Bil.var stack_register)) in
  let block = create_block_from_defs [def1; def2] in
  let state = update_block_analysis block fn_start_state project in
  let () = check "update_pointer_register" (Var.Map.find state.TypeInfo.reg register1 = Some(Ok(Pointer))) in
  let () = check "update_data_register" (Var.Map.find state.TypeInfo.reg register2 = Some(Ok(Data))) in
  let def1 = Def.create register1 (Bil.Load (Bil.var register1, Bil.var register2, Bitvector.LittleEndian, `r64) ) in
  let block = create_block_from_defs [def1;] in
  let state = update_block_analysis block fn_start_state project in
  let () = check "add_mem_address_registers" (Var.Map.find state.TypeInfo.reg register2 = Some(Ok(Pointer))) in
  ()

let test_update_stack () =
  let project = Option.value_exn !example_project in
  let bv x = Bitvector.of_int x ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8) in
  let stack_register = Symbol_utils.stack_register project in
  let fn_start_state = start_state stack_register project in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let register2 = Var.create "Register2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let mem_reg = Var.create "Mem_reg" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.binop Bil.AND (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create mem_reg (Bil.Store ((Bil.var mem_reg), (Bil.binop Bil.PLUS (Bil.var stack_register) (Bil.int (bv (-8)))), (Bil.var stack_register), Bitvector.LittleEndian, `r64)) in
  let def3 = Def.create register2 (Bil.Load (Bil.var register2, (Bil.binop Bil.MINUS (Bil.var stack_register) (Bil.int (bv 8))), Bitvector.LittleEndian, `r64) ) in
  let block = create_block_from_defs [def1; def2; def3;] in
  let state = update_block_analysis block fn_start_state project in
  let () = check "write_to_stack" ((Mem_region.get state.TypeInfo.stack (bv (-8))) = Some(Ok(Pointer))) in
  let () = check "load_from_stack" (Var.Map.find state.TypeInfo.reg register2 = Some(Ok(Pointer))) in
  ()


let tests = [
  "Update Stack Offset", `Quick, test_update_stack_offset;
  "Update Register", `Quick, test_update_reg;
  "Update Stack", `Quick, test_update_stack;
]
