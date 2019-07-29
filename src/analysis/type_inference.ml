open Bap.Std
open Core_kernel

(** TODO:
    interprocedural analysis
    backward analysis to recognize which constants are pointers and which not.
    maybe extend to track FunctionPointer,
    TODO: There are no checks yet if a value from the stack of the calling function
    is accessed. Maybe this should be part of another analysis.
    TODO: the fixpoint analysis does not track whether a pointer could have an
    unknown target as long as it has at least one known target. This should be
    tracked in an extra analysis step after the fixpoint analysis finished.
*)

let name = "Type Inference"
let version = "0.2"

(* TODO: result_option and result_map should be abstracted away into its own data type and into its own file. *)

(* generic merge of two ('a, unit) Result.t Option.t *)
let merge_result_option val1 val2 =
  match (val1, val2) with
  | (Some(Ok(x)), Some(Ok(y))) when x = y -> Some(Ok(x))
  | (Some(x), None)
  | (None, Some(x)) -> Some(x)
  | (None, None) -> None
  | _ -> Some(Error(()))

(* generic binop of two ('a, unit) Result.t Option.t *)
let binop_result_option val1 val2 ~op =
  match (val1, val2) with
  | (Some(Ok(x)), Some(Ok(y))) -> Some(Ok(op x y))
  | (Some(Ok(_)), None)
  | (None, Some(Ok(_))) -> None
  | (None, None) -> None
  | _ -> Some(Error(()))

(* generic merge of two ('a, unit) Result.t Map.t*)
let merge_result_map val1 val2 ~value_merge =
  Map.merge val1 val2 ~f:(fun ~key:_ values ->
    match values with
    | `Left(x)
    | `Right(x) -> Some(x)
    | `Both(Ok(x1), Ok(x2)) -> Some(value_merge x1 x2)
    | `Both(_, _) -> Some(Error(()))
  )

(* generic equal of two ('a, unit) Result.t Option.t)*)
let equal_result_option val1 val2 ~value_equal =
  match (val1, val2) with
  | (Some(Ok(x)), Some(Ok(y))) -> value_equal x y
  | (Some(Error(())), Some(Error(()))) -> true
  | (None, None) -> true
  | _ -> false


module PointerTargetInfo = struct
  type t = {
    offset: (Bitvector.t, unit) Result.t Option.t;
    alignment: (int, unit) Result.t Option.t;
  } [@@deriving bin_io, compare, sexp]

  let merge info1 info2 =
    { offset = merge_result_option info1.offset info2.offset;
      alignment = merge_result_option info1.alignment info2.alignment; }

  let equal info1 info2 =
    equal_result_option info1.offset info2.offset ~value_equal:Bitvector.(=) && equal_result_option info1.alignment info2.alignment ~value_equal: Int.(=)
end (* module *)


module Register = struct
  type t =
    | Pointer of PointerTargetInfo.t Tid.Map.t
    | Data
  [@@deriving bin_io, compare, sexp]

  let merge reg1 reg2 =
    match (reg1, reg2) with
    | (Pointer(target_info1), Pointer(target_info2)) ->
        Ok(Pointer(Map.merge target_info1 target_info2 ~f:(fun ~key:_ values ->
          match values with
          | `Left(info)
          | `Right(info) -> Some(info)
          | `Both(info1, info2) -> Some(PointerTargetInfo.merge info1 info2)
        )))
    | (Data, Data) -> Ok(Data)
    | _ -> Error(())

  (* Checks whether two registers hold the same data *)
  let equal reg1 reg2 =
    match (reg1, reg2) with
    | (Pointer(targets1), Pointer(targets2)) -> Map.equal PointerTargetInfo.equal targets1 targets2
    | (Data, Data) -> true
    | _ -> false

  (** add to the offsets of all possible targets of the register. *)
  let add_to_offsets register value_res_opt =
    match register with
    | Pointer(targets) ->
        let new_targets = Map.map targets ~f:(fun target ->
          { target with offset = binop_result_option target.offset value_res_opt ~op:Bitvector.(+) }
        ) in
        Pointer(new_targets)
    | Data -> Data

  (** subtract from the offsets of all possible targets of the register. *)
  let sub_from_offsets register value_res_opt =
    match register with
    | Pointer(targets) ->
        let new_targets = Map.map targets ~f:(fun target ->
          { target with offset = binop_result_option target.offset value_res_opt ~op:Bitvector.sub }
        ) in
        Pointer(new_targets)
    | Data -> Data

  (** sets all target offsets and alignments to unknown. Right now used as long as alignment tracking is not implemented. *)
  let set_unknown_offsets register =
    match register with
    | Pointer(targets) ->
        let new_targets = Map.map targets ~f:(fun _target -> { PointerTargetInfo.offset = None; alignment = None }) in
        Pointer(new_targets)
    | Data -> Data

end (* module *)


module TypeInfo = struct
  type reg_state = (Register.t, unit) Result.t Var.Map.t [@@deriving bin_io, compare, sexp]
  type t = {
    stack: Register.t Mem_region.t;
    reg: reg_state;
  } [@@deriving bin_io, compare, sexp]

  let merge state1 state2 =
    let stack = Mem_region.merge state1.stack state2.stack ~data_merge:(fun x y -> Some(Register.merge x y )) in
    let reg = merge_result_map state1.reg state2.reg ~value_merge:Register.merge in
    { stack = stack;
      reg = reg;
    }

    let equal state1 state2 =
      if Mem_region.equal state1.stack state2.stack ~data_equal:Register.equal then
         Map.equal (fun reg1 reg2 -> match (reg1, reg2) with
           | (Ok(register1), Ok(register2)) -> Register.equal register1 register2
           | (Error(()), Error(())) -> true
           | _ -> false
         ) state1.reg state2.reg
      else
        false

  (** Get an empty state. *)
  let empty () =
    { stack = Mem_region.empty ();
      reg = Var.Map.empty;
    }

  (** add flag register as known data register *)
  let add_flags state project =
    let flags = Symbol_utils.flag_register_list project in
    List.fold flags ~init:state ~f:(fun state register ->
      { state with reg = (Map.set state.reg ~key:register ~data:(Ok(Register.Data))) } )

  (** set stack register as known stack pointer. Deletes other targets of the stack pointer. *)
  let set_stack_register state ?offset ?alignment ~sub_tid ~project  =
    let stack_register = Symbol_utils.stack_register project in
    let offset = match offset with
      | Some(x) -> Some(Ok(x))
      | None -> None in
    let alignment = match alignment with
      | Some(x) -> Some(Ok(x))
      | None -> None in
    let stack_info = { PointerTargetInfo.offset = offset; alignment = alignment;} in
    let stack_target_map = Map.set Tid.Map.empty ~key:sub_tid ~data:stack_info in
    { state with reg = Map.set state.reg ~key:stack_register ~data:(Ok(Register.Pointer(stack_target_map))); }

  (** Returns a TypeInfo.t with only the stack pointer as pointer register (with
      unknown offset) and only the flag registers as data registers. The stack is empty. *)
  let only_stack_pointer_and_flags sub_tid project  =
    let state = empty () in
    let state = add_flags state project in
    let state = set_stack_register state ?offset:None ?alignment:None ~sub_tid ~project in
    state

  (** create a new state with stack pointer as known pointer register and all flag
      registers as known data registers. The stack itself is empty and the offset
      is 0. (TODO for interprocedural analysis: Ensure that the return address is
      marked as a pointer!) *)
  let function_start_state sub_tid project =
    let state = empty () in
    let state = add_flags state project in
    let zero_offset = Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8) in
    let state = set_stack_register state ~offset:zero_offset ?alignment:None ~sub_tid ~project in
    state

  let remove_virtual_registers state =
    { state with reg = Map.filter_keys state.reg ~f:(fun var -> Var.is_physical var) }

(** if the addr_exp is a (computable) stack offset, return the offset. In cases where addr_expr
    may or may not be a stack offset (i.e. offset of a register which may point to the stack or
    to some other memory region), it still returns an offset. *)
  let compute_stack_offset state addr_exp ~sub_tid ~project : Bitvector.t  Option.t =
    let (register, offset) = match addr_exp with
      | Bil.Var(var) -> (Some(var), Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8))
      | Bil.BinOp(Bil.PLUS, Bil.Var(var), Bil.Int(num)) -> (Some(var), num)
      | Bil.BinOp(Bil.MINUS, Bil.Var(var), Bil.Int(num)) -> (Some(var), Bitvector.neg (Bitvector.signed num))
      | _ -> (None, Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
    match register with
    | Some(var) ->
        begin match Map.find state.reg var with
        | Some(Ok(Pointer(targets))) ->
            begin match Map.find targets sub_tid with
            | Some(target_info) ->
                begin match target_info.offset with
                | Some(Ok(target_offset)) -> Some(Bitvector.(+) target_offset offset)
                | _ -> None
                end
            | None -> None
            end
        | _ -> None
        end
    | _ -> None

  (* Pretty printer that just prints the sexp. Needed for the creation of type_info_tag. *)
  let pp ppf elem =
    Format.fprintf ppf "%s" (Sexp.to_string (sexp_of_t elem))

end (* module *)

(* Create a tag for TypeInfo *)
let type_info_tag = Value.Tag.register (module TypeInfo)
    ~name:"type_info"
    ~uuid:"7a537f19-2dd1-49b6-b343-35b4b1d04c0b"

(** returns a list with all nested expressions. If expr1 is contained in expr2, then
    expr1 will be included after expr2 in the list. *)
let rec nested_exp_list exp : Exp.t list =
  let nested_exp = match exp with
    | Bil.Load(exp1, exp2, _, _) -> exp :: (nested_exp_list exp1) @ (nested_exp_list exp2)
    | Bil.Store(exp1, exp2, exp3, _, _) -> nested_exp_list exp1 @ nested_exp_list exp2 @ nested_exp_list exp3
    | Bil.BinOp(_op, exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2
    | Bil.UnOp(_op, exp1) -> nested_exp_list exp1
    | Bil.Var(_) -> []
    | Bil.Int(_) -> []
    | Bil.Cast(_, _, exp1) -> nested_exp_list exp1
    | Bil.Let(_, exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2
    | Bil.Unknown(_) -> []
    | Bil.Ite(exp1, exp2, exp3) -> nested_exp_list exp1 @ nested_exp_list exp2 @ nested_exp_list exp3
    | Bil.Extract(_, _, exp1) -> nested_exp_list exp1
    | Bil.Concat(exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2 in
  exp :: nested_exp


(** If exp is a load from the stack, return the corresponding element. If it may be
    a load from the stack, but could also be a load from some other memory region,
    we still assume that the type information on the stack is correct and return it.
    TODO: Bil.AND and Bil.OR are ignored, because we do not track alignment yet. *)
let get_stack_elem state exp ~sub_tid ~project =
  match exp with
  | Bil.Load(_, addr, _endian, size) -> begin (* TODO: add a test for correct endianess *)
      match TypeInfo.compute_stack_offset state addr ~sub_tid ~project with
      | Some(offset) -> begin
          match Mem_region.get state.TypeInfo.stack offset with
          | Some(Ok(elem, elem_size)) ->
            if Bitvector.to_int elem_size = Ok(Size.in_bytes size) then
              Some(Ok(elem))
            else
              Some(Error())
          | Some(Error()) -> Some(Error())
          | None -> None
        end
      | None -> None
    end
  | _ -> None

(* compute the value of an expression. This is a stub and will be replaced when we
   have a proper pass for value inference. *)
let value_of_exp exp =
  match exp with
  | Bil.Int(x) -> Some(Ok(x))
  | _ -> None


let rec type_of_exp exp (state: TypeInfo.t) ~sub_tid ~project =
  let open Register in
  match exp with
  | Bil.Load(_) -> (* TODO: Right now only the stack is tracked for type infos. *)
    get_stack_elem state exp ~sub_tid ~project
  | Bil.Store(_) -> None (* Stores are handled in another function. *)
  | Bil.BinOp(binop, exp1, exp2) -> begin
      match (binop, type_of_exp exp1 state ~sub_tid ~project, type_of_exp exp2 state ~sub_tid ~project) with
      (* pointer arithmetics *)
      | (Bil.PLUS, Some(Ok(Pointer(_))), Some(Ok(Pointer(_)))) -> Some(Error(()))
      | (Bil.PLUS, Some(Ok(Pointer(targets))), _summand) -> Some(Ok(Register.add_to_offsets (Pointer(targets)) (value_of_exp exp2)))
      | (Bil.PLUS, _summand, Some(Ok(Pointer(targets)))) -> Some(Ok(Register.add_to_offsets (Pointer(targets)) (value_of_exp exp1)))
      | (Bil.PLUS, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.PLUS, _, _) -> None
      | (Bil.MINUS, Some(Ok(Pointer(_))), Some(Ok(Pointer(_)))) -> Some(Ok(Data)) (* Pointer subtraction to determine offset is CWE-469, this should be logged. *)
      | (Bil.MINUS, Some(Ok(Pointer(targets))), _other) -> Some(Ok(Register.sub_from_offsets (Pointer(targets)) (value_of_exp exp2))) (* We assume that other is not a pointer. This can only generate errors in the presence of CWE-469 *)
      | (Bil.MINUS, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.MINUS, _, _) -> None
      (* bitwise AND and OR can be used as addition and subtraction if some alignment of the pointer is known *)
      | (Bil.AND, Some(Ok(Pointer(_))), Some(Ok(Pointer(_)))) -> Some(Error(())) (* TODO: This could be a pointer, but is there any case where this is used in practice? *)
      | (Bil.AND, Some(Ok(Pointer(targets))), _other)
      | (Bil.AND, _other, Some(Ok(Pointer(targets)))) -> Some(Ok(Register.set_unknown_offsets (Pointer(targets))))
      | (Bil.AND, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.AND, _, _) -> None
      | (Bil.OR, Some(Ok(Pointer(_))), Some(Ok(Pointer(_)))) -> Some(Error(())) (* TODO: This could be a pointer, but is there any case where this is used in practice? *)
      | (Bil.OR, Some(Ok(Pointer(targets))), _other)
      | (Bil.OR, _other, Some(Ok(Pointer(targets)))) -> Some(Ok(Register.set_unknown_offsets (Pointer(targets))))
      | (Bil.OR, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.OR, _, _) -> None
      | _ -> Some(Ok(Data)) (* every other operation should not yield valid pointers *)
    end
  | Bil.UnOp(_) -> Some(Ok(Data))
  | Bil.Var(var) -> Map.find state.TypeInfo.reg var
  | Bil.Int(_) -> None (* TODO: For non-relocateable binaries this could be a pointer to a function/global variable *)
  | Bil.Cast(Bil.SIGNED, _, _) -> Some(Ok(Data))
  | Bil.Cast(_, size, exp) ->
    if size = (Symbol_utils.arch_pointer_size_in_bytes project * 8) then type_of_exp exp state ~sub_tid ~project else Some(Ok(Data)) (* TODO: There is probably a special case when 64bit addresses are converted to 32bit addresses here, which can yield pointers *)
  | Bil.Let(_) -> None
  | Bil.Unknown(_) -> None
  | Bil.Ite(_if_, then_, else_) -> begin
      match (type_of_exp then_ state ~sub_tid ~project, type_of_exp else_ state ~sub_tid ~project) with
      | (Some(value1), Some(value2)) -> if value1 = value2 then Some(value1) else None
      | _ -> None
    end
  | Bil.Extract(_) -> Some(Ok(Data)) (* TODO: Similar to cast: Are there cases of 32bit-64bit-address-conversions here? *)
  | Bil.Concat(_) -> Some(Ok(Data)) (* TODO: If alignment of the pointer is known, it could be used like AND and OR *)

let pointer_size_as_bitvector project =
  let psize = Symbol_utils.arch_pointer_size_in_bytes project in
  Bitvector.of_int psize ~width:(psize * 8)


(* If exp is a store to the stack, add the corresponding value to the stack if possible. If the
   we cannot determine the value, delete the corresponding data on the stack.
   Custom behaviour if we cannot determine the exact position of the store or if it
   is unclear, whether it really was a store onto the stack or to somewhere else. *)
let set_stack_elem state exp ~sub_tid ~project =
  match exp with
  | Bil.Store(_, addr_exp, value_exp, _endian, size) ->
      let stack_offset = TypeInfo.compute_stack_offset state addr_exp ~sub_tid ~project in
      let value = type_of_exp value_exp state ~sub_tid ~project in
      let addr_type = type_of_exp addr_exp state ~sub_tid ~project in
      let (targets_stack, target_is_unique) = match addr_type with
        | Some(Ok(Pointer(targets))) -> (Option.is_some (Map.find targets sub_tid), Map.length targets = 1)
        | _ -> (false, false) in
      let pointer_size = Symbol_utils.arch_pointer_size_in_bytes project in
      if targets_stack then
          match stack_offset with
          | Some(offset) ->
              let new_stack =
                if Size.in_bytes size = pointer_size then
                  match value with
                  | Some(Ok(inner_value)) -> Mem_region.add state.TypeInfo.stack inner_value ~pos:offset ~size:(pointer_size_as_bitvector project)
                  | Some(Error(_)) -> Mem_region.mark_error state.TypeInfo.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:pointer_size)
                  | None -> Mem_region.remove state.TypeInfo.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:pointer_size)
                else (* store has to be data *)
                  Mem_region.add state.TypeInfo.stack Register.Data ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:pointer_size) in
              let new_state = { state with TypeInfo.stack = new_stack } in
              if target_is_unique then (* previous value on the stack gets overwritten *)
                new_state
              else (* previous value on the stack may have been overwritten. We merge the two possible states to account for both cases *)
                TypeInfo.merge state new_state
          | None -> begin
              if target_is_unique then (* There is a write on the stack, but we do not know where. To prevent our knowledge of the stack to get corrupted, we delete it. *)
                { state with TypeInfo.stack = Mem_region.empty ()}
              else (* There may have been a write to the stack, but we do not know where. We optimistically assume that if it was a write, it did not change the TypeInfo there. *)
                state
            end
      else (* store does not change the stack *)
        state
  | _ -> state

(* adds address registers of Loads and Stores to the list of known pointer register.
   Note that this is a source of pointers, where we do not know where they point to.
   This may confuse algorithms, if they assume that the pointer target list is exhaustive. *)
let add_mem_address_registers state exp ~sub_tid ~project =
  let exp_list = nested_exp_list exp in
  List.fold exp_list ~init:state ~f:(fun state exp ->
      match exp with
      | Bil.Load(_, addr_exp, _, _)
      | Bil.Store(_, addr_exp, _, _, _) -> begin
          match addr_exp with
          | Bil.Var(addr)
          | Bil.BinOp(Bil.PLUS, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.PLUS, Bil.Int(_), Bil.Var(addr))
          | Bil.BinOp(Bil.MINUS, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.AND, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.AND, Bil.Int(_), Bil.Var(addr))
          | Bil.BinOp(Bil.OR, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.OR, Bil.Int(_), Bil.Var(addr)) ->
              begin match Map.find state.TypeInfo.reg addr with
              | Some(Ok(Pointer(_))) -> state
              | _ ->   { state with TypeInfo.reg = Map.set state.TypeInfo.reg ~key:addr ~data:(Ok(Register.Pointer(Tid.Map.empty))) } (* TODO: there are some false positives here for indices in global data arrays, where the immediate is the pointer. Maybe remove all cases with potential false positives? *)
              end
          | Bil.BinOp(Bil.PLUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.PLUS, exp2, Bil.Var(addr))
          | Bil.BinOp(Bil.MINUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.AND, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.AND, exp2, Bil.Var(addr))
          | Bil.BinOp(Bil.OR, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.OR, exp2, Bil.Var(addr))            ->
            if type_of_exp exp2 state ~sub_tid ~project = Some(Ok(Register.Data)) then
              begin match Map.find state.TypeInfo.reg addr with
              | Some(Ok(Pointer(_))) -> state
              | _ ->   { state with TypeInfo.reg = Map.set state.TypeInfo.reg ~key:addr ~data:(Ok(Register.Pointer(Tid.Map.empty))) }
              end
            else
              state
          | _ -> state
        end
      | _ -> state
    )


(* Remove any knowledge of the stack (except the stack_offset) and the registers (except stack and flag registers) from the state. *)
let keep_only_stack_register state ~sub_tid ~project =
  let stack_pointer_value = Map.find state.TypeInfo.reg (Symbol_utils.stack_register project) in
  let new_state = TypeInfo.only_stack_pointer_and_flags sub_tid project in
  match stack_pointer_value with
  | Some(value) -> { new_state with TypeInfo.reg = Map.set state.reg ~key:(Symbol_utils.stack_register project) ~data:value }
  | None -> new_state

let update_state_def state def ~sub_tid ~project =
  (* add all registers that are used as address registers in load/store expressions to the state *)
  let state = add_mem_address_registers state (Def.rhs def) ~sub_tid ~project in
  (* update the lhs of the definition with its new type *)
  let state = match type_of_exp (Def.rhs def) state ~sub_tid ~project with
    | Some(value) ->
      let reg = Map.set state.TypeInfo.reg ~key:(Def.lhs def) ~data:value in
      { state with TypeInfo.reg = reg }
    | None -> (* We don't know the type of the new value *)
      let reg = Map.remove state.TypeInfo.reg (Def.lhs def) in
      { state with TypeInfo.reg = reg } in
  (* write something to the stack if the definition is a store to the stack *)
  let state = set_stack_elem state (Def.rhs def) ~sub_tid ~project in
  state

(** Add an integer to stack offset. *)
let add_to_stack_offset state num ~project =
  match Map.find state.TypeInfo.reg (Symbol_utils.stack_register project) with
  | Some(Ok(stack_register)) ->
      let pointer_size = Symbol_utils.arch_pointer_size_in_bytes project in
      let new_stack_value = Register.add_to_offsets stack_register (Some(Ok(Bitvector.of_int num ~width:(pointer_size * 8)))) in
      { state with TypeInfo.reg = Map.set state.TypeInfo.reg ~key:(Symbol_utils.stack_register project) ~data:(Ok(new_stack_value)) }
  | _ -> state (* There is no known stack offset, so we return the old state. *)

(* TODO: Add entry to config for this? Since type inference is its own bap-pass, this may need a new config file...
   Also important: update_state_jmp makes a lot of assumptions about the functions (like it does not interact with the stack).
   If this list gets configurable, we probably need a concept how to annotate these types of assumptions in config files. *)
(** returns a list of known malloc-like functions. *)
let malloc_like_function_list () =
  ["malloc"; "calloc"; "realloc";]

(** updates the state on a call to a malloc-like function. Notable assumptions for
    malloc-like functions:
    - only one return register, which returns a unique pointer to a newly allocated
      memory region. Note: Possible zero returns are handled by the CWE-476-check.
    - the malloc-like-function does not touch the stack
    - the standard calling convention of the target architecture is used. *)
let update_state_malloc_call state malloc_like_tid jmp_term ~project =
  (* only keep callee-saved register information. Stack information is also kept. TODO: maybe add a "cut"-function to remove all stack info below the stack pointer? *)
  let state = { state with TypeInfo.reg = Var.Map.filter_keys state.TypeInfo.reg ~f:(fun var -> Cconv.is_callee_saved var project) } in
  (* add the return register with its new pointer target. The target is identified by the tid of the jmp instruction. *)
  let malloc_like_fn = Term.find_exn sub_t (Project.program project) malloc_like_tid in
  let arguments = Term.enum arg_t malloc_like_fn in
  let return_arg_opt = Seq.find arguments ~f:(fun arg -> (* TODO: check whether there exists more than one return register! *)
    match Bap.Std.Arg.intent arg with
    | Some(Out) | Some(Both) -> true
    | _ -> false
  ) in
  let return_arg = match return_arg_opt with
    | Some(x) -> x
    | None -> failwith "[CWE-checker] malloc-like function has no return register" in
  let return_reg = match Bap.Std.Arg.rhs return_arg with
    | Bil.Var(var) -> var
    | _ -> failwith "[CWE-checker] Return register of malloc-like function wasn't a register." in
  let target_map = Map.set Tid.Map.empty ~key:(Term.tid jmp_term) ~data:{ PointerTargetInfo.offset = Some(Ok(Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8))); alignment = None} in
  { state with TypeInfo.reg = Var.Map.set state.reg ~key:return_reg ~data:(Ok(Pointer(target_map))) }


(* TODO: Right now the conditional expression is not checked! Thus for conditional calls
   (if bap generates conditional calls) the state would always be the state as if the call
   branch has been taken even for the other branch. The way that the bap fixpoint function
   works this could be quite complicated to implement. *)
let update_state_jmp state jmp ~sub_tid ~project =
  match Jmp.kind jmp with
  | Call(call) ->
      let return_state = match Call.target call with
      | Direct(tid) ->
        let func_name = match String.lsplit2 (Tid.name tid) ~on:'@' with
          | Some(_left, right) -> right
          | None -> Tid.name tid in
        if String.Set.mem (Cconv.parse_dyn_syms project) func_name then
          begin if List.exists (malloc_like_function_list ()) ~f:(fun elem -> elem = func_name) then
              update_state_malloc_call state tid jmp ~project
            else
              let empty_state = TypeInfo.empty () in (* TODO: to preserve stack information we need to be sure that the callee does not write on the stack. Can we already check that? *)
              { empty_state with
                TypeInfo.reg = Var.Map.filter_keys state.TypeInfo.reg ~f:(fun var -> Cconv.is_callee_saved var project) }
          end
        else
          keep_only_stack_register state ~sub_tid ~project (* TODO: add interprocedural analysis here. *)
      | Indirect(_) -> keep_only_stack_register state ~sub_tid ~project in (* TODO: when we have value tracking and interprocedural analysis, we can add indirect calls to the regular analysis. *)
      (* The callee is responsible for removing the return address from the stack, so we have to adjust the stack offset accordingly. *)
      (* TODO: x86/x64, arm, mips and ppc all use descending stacks and we assume here that a descending stack is used. Can this be checked by some info given from bap? Is there an architecture with an upward growing stack? *)
      add_to_stack_offset return_state (Symbol_utils.arch_pointer_size_in_bytes project) ~project
  | Int(_, _) -> (* TODO: We need stubs and/or interprocedural analysis here *)
      keep_only_stack_register state ~sub_tid ~project (* TODO: Are there cases where the stack offset has to be adjusted here? *)
  | Goto(Indirect(Bil.Var(var))) (* TODO: warn when jumping to something that is marked as data. *)
  | Ret(Indirect(Bil.Var(var))) ->
      begin match Map.find state.TypeInfo.reg var with
      | Some(Ok(Pointer(_))) -> state
      | _ ->   { state with TypeInfo.reg = Map.set state.TypeInfo.reg ~key:var ~data:(Ok(Register.Pointer(Tid.Map.empty))) }
      end
  | Goto(_)
  | Ret(_)    -> state

(* This is public for unit test purposes. *)
let update_type_info block_elem state ~sub_tid ~project =
  match block_elem with
  | `Def def -> update_state_def state def ~sub_tid ~project
  | `Phi _phi -> state (* We ignore phi terms for this analysis. *)
  | `Jmp jmp -> update_state_jmp state jmp ~sub_tid ~project

(** updates a block analysis. *)
let update_block_analysis block register_state ~sub_tid ~project =
  (* get all elements (Defs, Jumps, Phi-nodes) in the correct order *)
  let elements = Blk.elts block in
  let register_state = Seq.fold elements ~init:register_state ~f:(fun state element ->
      update_type_info element state ~sub_tid ~project
    ) in
  TypeInfo.remove_virtual_registers register_state (* virtual registers should not be accessed outside of the block where they are defined. *)


let intraprocedural_fixpoint func ~project =
  let cfg = Sub.to_cfg func in
  let sub_tid = Term.tid func in
  (* default state for nodes *)
  let only_sp = TypeInfo.only_stack_pointer_and_flags sub_tid project in
  try
    (* Create a starting solution where only the first block of a function knows the stack_offset. *)
    let fn_start_state = TypeInfo.function_start_state sub_tid project in
    let fn_start_block = Option.value_exn (Term.first blk_t func) in
    let fn_start_state = update_block_analysis fn_start_block fn_start_state ~sub_tid ~project in
    let fn_start_node = Seq.find_exn (Graphs.Ir.nodes cfg) ~f:(fun node -> (Term.tid fn_start_block) = (Term.tid (Graphs.Ir.Node.label node))) in
    let empty = Map.empty (module Graphs.Ir.Node) in
    let with_start_node = Map.set empty ~key:fn_start_node ~data:fn_start_state in
    let init = Graphlib.Std.Solution.create with_start_node only_sp in
    let equal = TypeInfo.equal in
    let merge = TypeInfo.merge in
    let f = (fun node state ->
        let block = Graphs.Ir.Node.label node in
        update_block_analysis block state ~sub_tid ~project
      ) in
    Graphlib.Std.Graphlib.fixpoint (module Graphs.Ir) cfg ~steps:100 ~rev:false ~init:init ~equal:equal ~merge:merge ~f:f
  with
  | _ -> (* An exception will be thrown if the function does not contain any blocks. In this case we can simply return an empty solution. *)
    Graphlib.Std.Solution.create (Map.empty (module Graphs.Ir.Node)) only_sp


(** Extract the starting state of a node. *)
let extract_start_state node ~cfg ~solution ~sub_tid ~project =
  let predecessors = Graphs.Ir.Node.preds node cfg in
  if Seq.is_empty predecessors then
    TypeInfo.function_start_state sub_tid project (* This should be the first block of a function. Maybe add a test for when there is more than one such block in a function? *)
  else
    let only_sp = TypeInfo.only_stack_pointer_and_flags sub_tid project in
    Seq.fold predecessors ~init:only_sp ~f:(fun state node ->
        TypeInfo.merge state (Graphlib.Std.Solution.get solution node)
      )


let compute_pointer_register project =
  let program = Project.program project in
  let program_with_tags = Term.map sub_t program ~f:(fun func ->
    let cfg = Sub.to_cfg func in
    let sub_tid = Term.tid func in
      let solution = intraprocedural_fixpoint func ~project in
      Seq.fold (Graphs.Ir.nodes cfg) ~init:func ~f:(fun func node ->
          let block = Graphs.Ir.Node.label node in
          let start_state = extract_start_state node ~cfg ~solution ~sub_tid ~project in
          let tagged_block = Term.set_attr block type_info_tag start_state in
          Term.update blk_t func tagged_block
        )
    ) in
  Project.with_program project program_with_tags

(** Prints type info to debug. *)
let print_type_info_to_debug state block_tid ~tid_map ~sub_tid ~project =
  let register_list = Map.fold state.TypeInfo.reg ~init:[] ~f:(fun ~key:var ~data:reg str_list ->
      match reg with
      | Ok(Register.Pointer(targets)) ->
          (Var.name var ^ ":Pointer(targets: " ^
           (Map.fold targets ~init:"" ~f:(fun ~key ~data:_ accum_string -> (Tid.name key) ^ "," ^ accum_string)) ^
           ")") :: str_list
      | Ok(Register.Data) -> (Var.name var ^ ":Data, ") :: str_list
      | Error(_) -> (Var.name var ^ ":Error, ") :: str_list ) in
  let register_string = String.concat register_list in
  let stack_offset_str =
    match Map.find state.TypeInfo.reg (Symbol_utils.stack_register project) with
    | Some(Ok(Pointer(targets))) ->
        begin match Map.find targets sub_tid with
        | Some(target) ->
            begin match target.PointerTargetInfo.offset with
            | Some(Ok(x)) ->
                begin match Bitvector.to_int (Bitvector.signed x) with
                | Ok(number) -> string_of_int number
                | _ -> "NaN"
                end
            | Some(Error()) -> "Unknown (Error)"
            | _ -> "Unknown"
            end
        | None -> "Unknown"
        end
    | _ -> "Unknown"
  in
  let debug_str = sprintf
                    "[%s] {%s} TypeInfo at %s:\nRegister: %s\nStackOffset: %s"
                    name
                    version
                    (Address_translation.translate_tid_to_assembler_address_string block_tid tid_map)
                    register_string
                    stack_offset_str in
  Log_utils.debug debug_str

let print_type_info_tags ~project ~tid_map =
  let program = Project.program project in
  let functions = Term.enum sub_t program in
  Seq.iter functions ~f:(fun func ->
    let sub_tid = Term.tid func in
      let blocks = Term.enum blk_t func in
      Seq.iter blocks ~f:(fun block ->
          match Term.get_attr block type_info_tag with
          | Some(start_state) -> print_type_info_to_debug start_state (Term.tid block) ~tid_map ~sub_tid ~project
          | None -> (* block has no type info tag, which should not happen *)
             let error_str = sprintf
                               "[%s] {%s} Block has no TypeInfo at %s (block TID %s)"
                               name
                               version
                               (Address_translation.translate_tid_to_assembler_address_string (Term.tid block) tid_map)
                               (Tid.name (Term.tid block)) in
             Log_utils.error error_str
        )
    )

(* Functions made available for unit tests *)
module Private = struct
  let update_block_analysis = update_block_analysis

  let function_start_state = TypeInfo.function_start_state

  let compute_stack_offset = TypeInfo.compute_stack_offset

  let only_stack_pointer_and_flags = TypeInfo.only_stack_pointer_and_flags

  let merge_type_infos = TypeInfo.merge

let type_info_equal = TypeInfo.equal
end
