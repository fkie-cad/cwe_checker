open Bap.Std
open Core_kernel.Std

(** TODO:
    interprocedural analysis
    backward analysis to recognize which constants are pointers and which not.
    extend to track FunctionPointer, DataPointer
    extend to track PointerTargets
    TODO: there are no checks yet if a value from the stack of the calling function
    is accessed.
*)

module Register = struct
  type t =
    | Pointer
    | Data

  let merge reg1 reg2 =
    if reg1 = reg2 then Some(Ok(reg1)) else Some(Error(()))

  let equal reg1 reg2 =
    reg1 = reg2
end


module State = struct
  type reg_state = (Register.t, unit) result Map.Make(Var).t
  type t = {
    stack: Register.t Mem_region.t;
    stack_offset: (Bitvector.t, unit) result option; (* If we don't know the offset, this is None, if we have conflicting values for the offset, this is Some(Error()) *)
    reg: reg_state;
  }

  let merge state1 state2 =
    let stack = Mem_region.merge state1.stack state2.stack ~data_merge:Register.merge in
    let stack_offset = match (state1.stack_offset, state2.stack_offset) with
      | (Some(Ok(x)), Some(Ok(y))) when x = y -> Some(Ok(x))
      | (Some(x), None)
      | (None, Some(x)) -> Some(x)
      | (None, None) -> None
      | _ -> Some(Error(())) in
    let reg = Map.merge state1.reg state2.reg ~f:(fun ~key values ->
        match values with
        | `Left(reg)
        | `Right(reg) -> Some(reg)
        | `Both(Ok(reg1), Ok(reg2)) -> Register.merge reg1 reg2
        | `Both(_, _) -> Some(Error(()))
      ) in
    { stack = stack;
      stack_offset = stack_offset;
      reg = reg }

  let equal state1 state2 =
    if state1.stack_offset = state2.stack_offset && (Mem_region.equal state1.stack state2.stack ~data_equal:Register.equal) then
      Map.equal (fun reg1 reg2 -> reg1 = reg2) state1.reg state2.reg
    else
      false

  (** create a new state with stack pointer as known pointer register and all flag
      registers as known data registers. The stack itself is empty (TODO: Maybe add
      return address to stack) and the offset is 0 (TODO: check correctness). *)
  let stack_pointer_and_flags project =
    let module VarMap = Map.Make(Var) in
    let stack_pointer = Symbol_utils.stack_register project in
    let reg = Map.add VarMap.empty ~key:stack_pointer ~data:(Ok(Register.Pointer)) in
    let flags = Symbol_utils.flag_register_list project in
    let reg = List.fold flags ~init:reg ~f:(fun state register ->
        Map.add state register (Ok(Register.Data)) ) in
    { stack = Mem_region.empty ();
      stack_offset = Some(Ok(Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8))); (* TODO: Check whether this is correct. *)
      reg = reg;
    }

  let remove_virtual_registers state = (* TODO: maybe remove all that is neither a register nor a flag instead *)
    { state with reg = Map.filter_keys state.reg ~f:(fun var -> Var.is_physical var) }

  let stack_offset_add state (value:Bitvector.t) =
    match state.stack_offset with
    | Some(Ok(x)) -> { state with stack_offset = Some(Ok(Bitvector.(+) x value)) }
    | _ -> state

  (** if the addr_exp is a (computable) stack offset, return the offset *)
  let compute_stack_offset state addr_exp ~project =
    let (register, offset) = match addr_exp with
      | Bil.Var(var) -> (Some(var), Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8))
      | Bil.BinOp(Bil.PLUS, Bil.Var(var), Bil.Int(num)) -> (Some(var), num)
      | Bil.BinOp(Bil.MINUS, Bil.Var(var), Bil.Int(num)) -> (Some(var), Bitvector.neg (Bitvector.signed num))
      | _ -> (None, Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
    match (register, state.stack_offset) with
    | (Some(var), Some(Ok(base_offset))) when var = (Symbol_utils.stack_register project) -> Some(Bitvector.(+) base_offset offset)
    | _ -> None

end (* module *)


(** returns a list with all nested expressions. If expr1 is contained in expr2, then
    expr1 will be included after expr2 in the list.
    TODO: decide whether to implement the functionality with Exp.visitor instead. *)
let rec nested_exp_list exp : Exp.t list =
  let nested_exp = match exp with
    | Bil.Load(exp1, exp2, _, _) -> exp :: (nested_exp_list exp1) @ (nested_exp_list exp2)
    | Bil.Store(exp1, exp2, exp3, _, _) -> nested_exp_list exp1 @ nested_exp_list exp2 @ nested_exp_list exp3
    | Bil.BinOp(op, exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2
    | Bil.UnOp(op, exp1) -> nested_exp_list exp1
    | Bil.Var(_) -> []
    | Bil.Int(_) -> []
    | Bil.Cast(_, _, exp1) -> nested_exp_list exp1
    | Bil.Let(_, exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2
    | Bil.Unknown(_) -> []
    | Bil.Ite(exp1, exp2, exp3) -> nested_exp_list exp1 @ nested_exp_list exp2 @ nested_exp_list exp3
    | Bil.Extract(_, _, exp1) -> nested_exp_list exp1
    | Bil.Concat(exp1, exp2) -> nested_exp_list exp1 @ nested_exp_list exp2 in
  exp :: nested_exp


(** If exp is a load from the stack, return the corresponding element.
    TODO: Bil.AND and Bil.OR are ignored, because we do not track alignment yet. *)
let get_stack_elem state exp ~project =
  match exp with
  | Bil.Load(_, addr, endian, size) when (Size.in_bytes size) = (Symbol_utils.arch_pointer_size_in_bytes project) -> begin (* TODO: add a test for correct endianess *)
      match State.compute_stack_offset state addr project with
      | Some(offset) -> Mem_region.get state.State.stack offset
      | None -> None
    end
  | _ -> None




let rec type_of_exp exp (state: State.t) ~project =
  let open Register in
  match exp with
  | Bil.Load(_) -> (* TODO: Right now only the stack is tracked for type infos. *)
    get_stack_elem state exp ~project
  | Bil.Store(_) -> None (* TODO: when we have type infos on memory regions we have to store type infos here. *)
  | Bil.BinOp(binop, exp1, exp2) -> begin
      match (binop, type_of_exp exp1 state project, type_of_exp exp2 state project) with
      (* pointer arithmetics *)
      | (Bil.PLUS, Some(Ok(Pointer)), Some(Ok(Pointer))) -> Some(Error(()))
      | (Bil.PLUS, Some(Ok(Pointer)), other)
      | (Bil.PLUS, other, Some(Ok(Pointer))) -> Some(Ok(Pointer))
      | (Bil.PLUS, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.PLUS, _, _) -> None
      | (Bil.MINUS, Some(Ok(Pointer)), Some(Ok(Pointer))) -> Some(Ok(Data)) (* Pointer subtraction to determine offset is CWE-469, this should be logged. *)
      | (Bil.MINUS, Some(Ok(Pointer)), other) -> Some(Ok(Pointer)) (* We assume that other is not a pointer. This can only generate errors in the presence of CWE-469 *)
      | (Bil.MINUS, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.MINUS, _, _) -> None
      (* bitwise AND and OR can be used as addition and subtraction if some alignment of the pointer is known *)
      | (Bil.AND, Some(Ok(Pointer)), Some(Ok(Pointer))) -> Some(Error(())) (* TODO: This could be a pointer, but is there any case where this is used in practice? *)
      | (Bil.AND, Some(Ok(Pointer)), other)
      | (Bil.AND, other, Some(Ok(Pointer))) -> Some(Ok(Pointer))
      | (Bil.AND, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.AND, _, _) -> None
      | (Bil.OR, Some(Ok(Pointer)), Some(Ok(Pointer))) -> Some(Error(())) (* TODO: This could be a pointer, but is there any case where this is used in practice? *)
      | (Bil.OR, Some(Ok(Pointer)), other)
      | (Bil.OR, other, Some(Ok(Pointer))) -> Some(Ok(Pointer))
      | (Bil.OR, Some(Ok(Data)), Some(Ok(Data))) -> Some(Ok(Data))
      | (Bil.OR, _, _) -> None
      | _ -> Some(Ok(Data)) (* every other operation should not yield valid pointers *)
    end
  | Bil.UnOp(_) -> Some(Ok(Data))
  | Bil.Var(var) -> Map.find state.State.reg var
  | Bil.Int(_) -> None (* TODO: For non-relocateable binaries this could be a pointer to a function/global variable *)
  | Bil.Cast(Bil.SIGNED, _, _) -> Some(Ok(Data))
  | Bil.Cast(_, size, exp) -> (* TODO: unit test, whether size here is really in bits??? *)
    if size = (Symbol_utils.arch_pointer_size_in_bytes project * 8) then type_of_exp exp state project else Some(Ok(Data)) (* TODO: There is probably a special case when 64bit addresses are converted to 32bit addresses here, which can yield pointers *)
  | Bil.Let(_) -> None (* TODO: Make sure that all let bindings are removed if possible *)
  | Bil.Unknown(_) -> None
  | Bil.Ite(if_, then_, else_) -> begin (* TODO: This is not exhaustive. *)
      match (type_of_exp then_ state project, type_of_exp else_ state project) with
      | (Some(value1), Some(value2)) -> if value1 = value2 then Some(value1) else None
      | _ -> None
    end
  | Bil.Extract(_) -> Some(Ok(Data)) (* TODO: Similar to cast: Are there cases of 32bit-64bit-address-conversions here? *)
  | Bil.Concat(_) -> Some(Ok(Data)) (* TODO: If alignment of the pointer is known, it could be used like AND and OR *)

let pointer_size_as_bitvector project =
  let psize = Symbol_utils.arch_pointer_size_in_bytes project in
  Bitvector.of_int psize ~width:(psize * 8)

(* If exp is a store to the stack, add the corresponding value to the stack. If the
   we cannot determine the value, delete the corresponding data on the stack. *)
let set_stack_elem state exp ~project =
  match exp with
  | Bil.Store(_, addr_exp, value_exp, endian, size) ->
    begin
      match (State.compute_stack_offset state addr_exp project, type_of_exp value_exp state ~project) with
      | (Some(offset), Some(Ok(value))) when Size.in_bytes size = (Symbol_utils.arch_pointer_size_in_bytes project) ->
        let stack = Mem_region.add state.State.stack value ~pos:offset ~size:(pointer_size_as_bitvector project) in
        { state with State.stack = stack}
      | (Some(offset), Some(Ok(value))) when Size.in_bytes size <> (Symbol_utils.arch_pointer_size_in_bytes project) ->
        let stack = Mem_region.add state.State.stack Register.Data ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with State.stack = stack}
      | (Some(offset), Some(Error(_))) ->
        let stack = Mem_region.mark_error state.State.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with State.stack = stack}
      | (Some(offset), None) ->
        let stack = Mem_region.remove state.State.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with State.stack = stack}
      | _ -> state
    end
  | _ -> state

let add_mem_address_registers state exp ~project =
  let exp_list = nested_exp_list exp in
  List.fold exp_list ~init:state ~f:(fun state exp ->
      match exp with
      | Bil.Load(_, addr_exp, _, _)
      | Bil.Store(_, addr_exp, _, _, _) -> begin
          match addr_exp with
          | Bil.Var(addr)
          | Bil.BinOp(Bil.PLUS, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.MINUS, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.AND, Bil.Var(addr), Bil.Int(_))
          | Bil.BinOp(Bil.OR, Bil.Var(addr), Bil.Int(_)) ->
            { state with State.reg = Map.add state.State.reg addr (Ok(Register.Pointer)) } (* TODO: there are some false positives here for indices in global data array, where the immediate is the pointer. *)
          | Bil.BinOp(Bil.PLUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.MINUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.AND, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.OR, Bil.Var(addr), exp2) ->
            if type_of_exp exp2 state project = Some(Ok(Register.Data)) then
              { state with State.reg = Map.add state.State.reg addr (Ok(Register.Pointer)) }
            else
              state
          | _ -> state
        end
      | _ -> state
    )


(* updates the stack offset if a definition changes the stack pointer value.
   TODO: Bil.AND, Bil.OR are ignored because we do not track alignment yet. *)
let update_stack_offset state def ~project =
  let stack_register = Symbol_utils.stack_register project in
  if Def.lhs def = stack_register && Option.is_some state.State.stack_offset then
    match Def.rhs def with
    | Bil.BinOp(Bil.PLUS, Bil.Var(var), Bil.Int(value)) ->
      if var = stack_register then
        State.stack_offset_add state value
      else
        { state with State.stack_offset = None }
    | Bil.BinOp(Bil.MINUS, Bil.Var(var), Bil.Int(value)) ->
      if var = stack_register then
        State.stack_offset_add state (Bitvector.neg (Bitvector.signed value))
      else
        { state with State.stack_offset = None }
    | _ -> { state with State.stack_offset = None }
  else
    state

let update_state_def state def ~project =
  (* add all registers that are used as address registers in load/store expressions to the state *)
  let state = add_mem_address_registers state (Def.rhs def) project in
  let state = match type_of_exp (Def.rhs def) state project with
    | Some(value) ->
      let reg = Map.add state.State.reg (Def.lhs def) value in
      { state with State.reg = reg }
    | None -> (* We don't know the type of the new value *)
      let reg = Map.remove state.State.reg (Def.lhs def) in
      { state with State.reg = reg } in
  (* update stack offset and maybe write something to the stack *)
  let state = update_stack_offset state def ~project in
  let state = set_stack_elem state (Def.rhs def) ~project in
  state

let update_state_jmp state jmp ~project =
  match Jmp.kind jmp with
  | Call(_)
  | Int(_, _) -> State.stack_pointer_and_flags project (* TODO: We need stubs and/or interprocedural analysis here *)
  | Goto(Indirect(Bil.Var(var))) (* TODO: warn when jumping to something that is marked as data. *)
  | Ret(Indirect(Bil.Var(var))) ->
    let reg = Map.add state.State.reg var (Ok(Register.Pointer)) in
    { state with State.reg = reg }
  | Goto(_)
  | Ret(_)    -> state

(** updates a block analysis. *)
let update_block_analysis block register_state ~project =
  (* get all elements (Defs, Jumps, Phi-nodes) in the correct order *)
  let elements = Blk.elts block in
  let register_state = Seq.fold elements ~init:register_state ~f:(fun state element ->
      match element with
      | `Def def -> update_state_def state def ~project
      | `Phi phi -> state (* We ignore phi terms for this analysis. *)
      | `Jmp jmp -> update_state_jmp state jmp ~project
    ) in
  State.remove_virtual_registers register_state (* virtual registers should not be accessed outside of the block where they are defined. *)


let intraprocedural_fixpoint func ~project =
  let cfg = Sub.to_cfg func in
  let only_sp = State.stack_pointer_and_flags project in
  let empty = Map.empty Graphs.Ir.Node.comparator in
  let init = Graphlib.Std.Solution.create empty only_sp in
  let equal = State.equal in
  let merge = State.merge in
  let f = (fun node state ->
      let block = Graphs.Ir.Node.label node in
      update_block_analysis block state ~project
    ) in
  Graphlib.Std.Graphlib.fixpoint (module Graphs.Ir) cfg ~steps:100 ~rev:false ~init:init ~equal:equal ~merge:merge ~f:f

(** Extract the starting state of a node. *)
let extract_start_state node ~cfg ~solution ~project =
let predecessors = Graphs.Ir.Node.preds node cfg in
Seq.fold predecessors ~init:(State.stack_pointer_and_flags project) ~f:(fun state node ->
    State.merge state (Graphlib.Std.Solution.get solution node)
  )

(* TODO: remove or refactor to also print stack info. *)
let print_state state =
  print_string "Register: ";
  Map.iteri state.State.reg ~f:(fun ~key:var ~data:reg ->
      match reg with
      | Ok(Register.Pointer) -> print_string (Var.name var ^ ":Pointer, ")
      | Ok(Register.Data) -> print_string (Var.name var ^ ":Data, ")
      | Error(_) -> print_string (Var.name var ^ ":Error, ")
    );
  print_endline ""

(** Returns a list of pairs (tid, state) for each def in a (blk_t-)node. The state
is the state _after execution of the node. *)
let state_list_def node ~cfg ~solution ~project =
  let input_state = extract_start_state node ~cfg ~solution ~project in
  let block = Graphs.Ir.Node.label node in
  let defs = Term.enum def_t block in
  let (output, _) = Seq.fold defs ~init:([], input_state) ~f:(fun (list_, state) def ->
      let state = update_state_def state def project in
      ( (Term.tid def, state) :: list_, state)
    ) in
  output


let compute_pointer_register project =
  let output_map = Map.empty Tid.comparator in
  let program = Project.program project in
  let functions = Term.enum sub_t program in
  Seq.fold functions ~init:output_map ~f:(fun output_map func ->
      let cfg = Sub.to_cfg func in
      let solution = intraprocedural_fixpoint func project in
      Seq.fold (Graphs.Ir.nodes cfg) ~init:output_map ~f:(fun output_map node ->
          let block = Graphs.Ir.Node.label node in
          Map.add output_map (Term.tid block) (extract_start_state node cfg solution project)
        )
    )

let print_blocks_with_error_register state_map ~project =
  let program = Project.program project in
  let functions = Term.enum sub_t program in
  Seq.iter functions ~f:(fun func ->
      let blocks = Term.enum blk_t func in
      Seq.iter blocks ~f:(fun block ->
          let start_state = Map.find_exn state_map (Term.tid block) in
          let end_state = update_block_analysis block start_state project in
          if Map.exists end_state.reg ~f:(fun register -> register = Error(())) then
            let () = print_string (Blk.pps () block) in
            print_state end_state
        )
    )
