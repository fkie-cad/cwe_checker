open Bap.Std
open Core_kernel
open Cwe_checker_core

open Type_inference
open Type_inference.Private

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None

(** create a bitvector with value x and width the width of pointers in the example project. *)
let bv x =
  Bitvector.of_int x ~width:(Symbol_utils.arch_pointer_size_in_bytes (Option.value_exn !example_project) * 8)

(* TODO: As soon as more pointers than stack pointer are tracked, add more tests! *)

let create_block_from_defs def_list =
  let block = Blk.Builder.create () in
  let () = List.iter def_list ~f:(fun def -> Blk.Builder.add_def block def) in
  Blk.Builder.result block

let test_preamble () =
  let project = Option.value_exn !example_project in
  let stack_register = Symbol_utils.stack_register project in
  let sub = Sub.create ~name:"TestSub" () in
  let sub_tid = Term.tid sub in
  let fn_start_state = function_start_state sub_tid project in
  (project, stack_register, sub, sub_tid, fn_start_state)

let test_update_stack_offset () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let def1 = Def.create stack_register (Bil.binop Bil.plus (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create stack_register (Bil.binop Bil.minus (Bil.var stack_register) (Bil.int (bv 16))) in
  let block = create_block_from_defs [def1; def2] in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "update_stack_offset" ( (compute_stack_offset state (Bil.var stack_register) ~sub_tid ~project) = Some(Bitvector.unsigned (bv (-8)))) in
  ()

let test_preserve_stack_offset_on_stubs () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let mem_reg = Var.create "Mem_reg" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.unop Bil.NEG (Bil.var register1)) in
  let def2 = Def.create mem_reg (Bil.Store ((Bil.var mem_reg), (Bil.binop Bil.PLUS (Bil.var stack_register) (Bil.int (bv (-8)))), (Bil.var register1), Bitvector.LittleEndian, `r64)) in
  let call_term = Jmp.create (Call (Call.create ~target:(Label.direct sub_tid) () )) in
  let block = Blk.Builder.create () in
  let () = Blk.Builder.add_def block def1 in
  let () = Blk.Builder.add_def block def2 in
  let () = Blk.Builder.add_jmp block call_term in
  let block = Blk.Builder.result block in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let pointer_size = Symbol_utils.arch_pointer_size_in_bytes project in (* since the callee removes the return address from the stack, the stack offset is adjusted accordingly. *)
  let () = check "preserve_stack_offset_inner_call" ( (compute_stack_offset state (Bil.var stack_register) ~sub_tid ~project) = Some(Bitvector.unsigned (bv pointer_size))) in
  let () = check "delete_stack_info_inner_call" (Mem_region.get state.TypeInfo.stack (bv (-8)) = None) in
  (* find the malloc extern call. This fails if the example project does not contain a call to malloc. *)
  let malloc_sub = Seq.find_exn (Term.enum sub_t (Project.program project)) ~f:(fun sub -> Sub.name sub = "malloc") in
  let call_term = Jmp.create (Call (Call.create ~target:(Label.direct (Term.tid malloc_sub)) () )) in
  let block = Blk.Builder.create () in
  let () = Blk.Builder.add_def block def1 in
  let () = Blk.Builder.add_def block def2 in
  let () = Blk.Builder.add_jmp block call_term in
  let block = Blk.Builder.result block in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "preserve_stack_offset_extern_malloc_call" ( (compute_stack_offset state (Bil.var stack_register) ~sub_tid ~project) = Some(Bitvector.unsigned (bv pointer_size))) in
  let () = check "preserve_stack_info_extern_malloc_call" (Mem_region.get state.TypeInfo.stack (bv (-8)) = Some(Ok((Data, bv 8)))) in
  (* find the "free" extern call. This fails if the example project does not contain a call to "free". *)
  let extern_sub = Seq.find_exn (Term.enum sub_t (Project.program project)) ~f:(fun sub -> Sub.name sub = "free") in
  let call_term = Jmp.create (Call (Call.create ~target:(Label.direct (Term.tid extern_sub)) () )) in
  let block = Blk.Builder.create () in
  let () = Blk.Builder.add_def block def1 in
  let () = Blk.Builder.add_def block def2 in
  let () = Blk.Builder.add_jmp block call_term in
  let block = Blk.Builder.result block in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "preserve_stack_offset_extern_call" ( (compute_stack_offset state (Bil.var stack_register) ~sub_tid ~project) = Some(Bitvector.unsigned (bv pointer_size))) in
  let () = check "delete_stack_info_extern_call" (Mem_region.get state.TypeInfo.stack (bv (-8)) <> Some(Ok((Data, bv 8)))) in
  ()

let test_update_reg () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let register2 = Var.create "Register2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.binop Bil.AND (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create register2 (Bil.binop Bil.XOR (Bil.var register1) (Bil.var stack_register)) in
  let block = create_block_from_defs [def1; def2] in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "update_pointer_register" (
    match Var.Map.find state.TypeInfo.reg register1 with
    | Some(Ok(Pointer(_))) -> true
    |_ -> false
  ) in
  let () = check "update_data_register" (Var.Map.find state.TypeInfo.reg register2 = Some(Ok(Data))) in
  let def1 = Def.create register1 (Bil.Load (Bil.var register1, Bil.var register2, Bitvector.LittleEndian, `r64) ) in
  let block = create_block_from_defs [def1;] in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "add_mem_address_registers" (
    match Var.Map.find state.TypeInfo.reg register2 with
    | Some(Ok(Pointer(_))) -> true
    | _ -> false
  ) in
  ()

let test_update_stack () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let register2 = Var.create "Register2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let mem_reg = Var.create "Mem_reg" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.binop Bil.AND (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create mem_reg (Bil.Store ((Bil.var mem_reg), (Bil.binop Bil.PLUS (Bil.var stack_register) (Bil.int (bv (-8)))), (Bil.var stack_register), Bitvector.LittleEndian, `r64)) in
  let def3 = Def.create register2 (Bil.Load (Bil.var mem_reg, (Bil.binop Bil.MINUS (Bil.var stack_register) (Bil.int (bv 8))), Bitvector.LittleEndian, `r64) ) in
  let block = create_block_from_defs [def1; def2; def3;] in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "write_to_stack" (
    match Mem_region.get state.TypeInfo.stack (bv (-8)) with
    | Some(Ok(Pointer(_targets), size )) when size = bv (Symbol_utils.arch_pointer_size_in_bytes project) -> true
    | _ -> false
  ) in
  let () = check "load_from_stack" (
    match Var.Map.find state.TypeInfo.reg register2 with
    | Some(Ok(Pointer(_))) -> true
    | _ -> false
  ) in
  ()

let test_address_registers_on_load_and_store () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let register1 = Var.create "Register1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let register2 = Var.create "Register2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let mem_reg = Var.create "Mem_reg" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
  let def1 = Def.create register1 (Bil.binop Bil.XOR (Bil.var stack_register) (Bil.int (bv 8))) in
  let def2 = Def.create mem_reg (Bil.Store ((Bil.var mem_reg), (Bil.var register1) , (Bil.var stack_register), Bitvector.LittleEndian, `r64)) in
  let def3 = Def.create register2 (Bil.Load (Bil.var mem_reg, (Bil.binop Bil.MINUS (Bil.var stack_register) (Bil.int (bv 8))), Bitvector.LittleEndian, `r64) ) in
  let block = create_block_from_defs [def1; def2; def3;] in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  let () = check "mark_store_address_as_pointer" (
    match Map.find_exn state.TypeInfo.reg register1 with
    | Ok(Pointer(targets)) -> (Map.is_empty targets)
    | _ -> false
  ) in
  let () = check "dont_change_offsets_on_address_register" (compute_stack_offset state (Bil.var stack_register) ~sub_tid ~project = Some(bv 0)) in
  ()

let test_merge_type_infos () =
  let (project, stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let generic_empty_state = only_stack_pointer_and_flags sub_tid project in
  let def1 = Def.create stack_register (Bil.binop Bil.plus (Bil.var stack_register) (Bil.int (bv 8))) in
  let block = create_block_from_defs [def1;] in
  let state1 = update_block_analysis block fn_start_state ~sub_tid ~project in
  let state2 = update_block_analysis block generic_empty_state ~sub_tid ~project in
  let merged_state = merge_type_infos state1 state1 in
  let () = check "merge_same_stack_offset" (compute_stack_offset merged_state (Bil.var stack_register) ~sub_tid ~project = Some(Bitvector.unsigned (bv 8))) in
  let merged_state = merge_type_infos fn_start_state state1 in
  let () = check "merge_different_stack_offsets" (compute_stack_offset merged_state (Bil.var stack_register) ~sub_tid ~project = None) in
  let merged_state = merge_type_infos generic_empty_state state1 in
  let () = check "merge_with_unknown_stack_offset" (compute_stack_offset merged_state (Bil.var stack_register) ~sub_tid ~project = Some(Bitvector.unsigned (bv 8))) in
  let merged_state = merge_type_infos generic_empty_state state2 in
  let () = check "merge_empty_stack_offsets" (compute_stack_offset merged_state (Bil.var stack_register) ~sub_tid ~project = None) in
  ()

let test_type_info_equal () =
  let (project, _stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  let generic_empty_state = only_stack_pointer_and_flags sub_tid project in
  let () = check "empty_state_neq_fn_start_state" (false = (type_info_equal fn_start_state generic_empty_state)) in
  ()

let test_malloc_call_return_reg () =
  let (project, _stack_register, _sub, sub_tid, fn_start_state) = test_preamble () in
  (* find the malloc extern call. This fails if the example project does not contain a call to malloc. *)
  let malloc_sub = Seq.find_exn (Term.enum sub_t (Project.program project)) ~f:(fun sub -> Sub.name sub = "malloc") in
  let call_term = Jmp.create (Call (Call.create ~target:(Label.direct (Term.tid malloc_sub)) () )) in
  let block = Blk.Builder.create () in
  let () = Blk.Builder.add_jmp block call_term in
  let block = Blk.Builder.result block in
  let state = update_block_analysis block fn_start_state ~sub_tid ~project in
  (* test whether the return register is marked as a pointer register. This fails if the example project is not a x64 binary. *)
  let state_reg_list = Map.to_alist state.TypeInfo.reg in
  let () = String.Set.iter (Cconv.parse_dyn_syms project) ~f:(fun elem -> print_endline elem) in
  let () = check "malloc_return_register_marked" (match List.find state_reg_list ~f:(fun (var, _register_info) -> Var.name var = "RAX") with
    | Some((_var, register_info)) ->  (* TODO: test whether the target is set correctly. *)
        begin match register_info with
        | Ok(Pointer(targets)) ->
            begin match Map.to_alist targets with
            | (target_tid, _) :: [] -> target_tid = Term.tid call_term
            | _ -> false
            end
        | _ -> false
        end
    | None -> false
  ) in
  ()


let tests = [
  "Update Stack Offset", `Quick, test_update_stack_offset;
  "Update Register", `Quick, test_update_reg;
  "Update Stack", `Quick, test_update_stack;
  "Preserve Stack data on calls", `Quick, test_preserve_stack_offset_on_stubs;
  "Merge TypeInfos", `Quick, test_merge_type_infos;
  "Equality check for TypeInfos", `Quick, test_type_info_equal;
  "Address register handling on load/store instructions", `Quick, test_address_registers_on_load_and_store;
  "Malloc calls mark return register", `Quick, test_malloc_call_return_reg;
]
