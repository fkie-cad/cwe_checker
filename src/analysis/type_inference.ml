open Bap.Std
open Core_kernel.Std

(** TODO:
    interprocedural analysis
    backward analysis to recognize which constants are pointers and which not.
    extend to track FunctionPointer, DataPointer
    extend to track PointerTargets
    TODO: there are no checks yet if a value from the stack of the calling function
    is accessed.
    TODO: tracking for PointerTargets should also track if another register other
    than the stack register is used to access values on the stack of the current
    function.
*)

module Register = struct
  type t =
    | Pointer
    | Data
  [@@deriving bin_io, compare, sexp]

  let merge reg1 reg2 =
    if reg1 = reg2 then Some(Ok(reg1)) else Some(Error(()))

  let equal reg1 reg2 =
    reg1 = reg2
end


module TypeInfo = struct
  type reg_state = (Register.t, unit) Result.t Var.Map.t [@@deriving bin_io, compare, sexp]
  type t = {
    stack: Register.t Mem_region.t;
    stack_offset: (Bitvector.t, unit) Result.t Option.t; (* If we don't know the offset, this is None, if we have conflicting values for the offset, this is Some(Error()) *)
    reg: reg_state;
  } [@@deriving bin_io, compare, sexp]

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

  (** Get an empty state. *)
  let empty () =
    let module VarMap = Var.Map in
    { stack = Mem_region.empty ();
      stack_offset = None;
      reg = VarMap.empty;
    }

  (** Returns a register list with only the stack pointer as pointer register and
      only the flag registers as data registers. *)
  let get_stack_pointer_and_flags project =
    let module VarMap = Var.Map in
    let stack_pointer = Symbol_utils.stack_register project in
    let reg = Map.add VarMap.empty ~key:stack_pointer ~data:(Ok(Register.Pointer)) in
    let flags = Symbol_utils.flag_register_list project in
    List.fold flags ~init:reg ~f:(fun state register ->
        Map.add state register (Ok(Register.Data)) )

  (** create a new state with stack pointer as known pointer register and all flag
      registers as known data registers. The stack itself is empty and the offset
      is 0. (TODO for interprocedural analysis: Ensure that the return address is
      marked as a pointer!) *)
  let function_start_state project =
    let module VarMap = Var.Map in
    let reg = get_stack_pointer_and_flags project in
    { stack = Mem_region.empty ();
      stack_offset = Some(Ok(Bitvector.of_int 0 ~width:(Symbol_utils.arch_pointer_size_in_bytes project * 8)));
      reg = reg;
    }

  let remove_virtual_registers state =
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
  | Bil.Load(_, addr, endian, size) -> begin (* TODO: add a test for correct endianess *)
      match TypeInfo.compute_stack_offset state addr project with
      | Some(offset) -> begin
          match Mem_region.get state.TypeInfo.stack offset with
          | Some(Ok(elem, elem_size)) ->
            if Bitvector.to_int_exn elem_size = (Size.in_bytes size) then
              Some(Ok(elem))
            else
              Some(Error())
          | Some(Error()) -> Some(Error())
          | None -> None
        end
      | None -> None
    end
  | _ -> None




let rec type_of_exp exp (state: TypeInfo.t) ~project =
  let open Register in
  match exp with
  | Bil.Load(_) -> (* TODO: Right now only the stack is tracked for type infos. *)
    get_stack_elem state exp ~project
  | Bil.Store(_) -> None (* Stores are handled in another function. *)
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
  | Bil.Var(var) -> Map.find state.TypeInfo.reg var
  | Bil.Int(_) -> None (* TODO: For non-relocateable binaries this could be a pointer to a function/global variable *)
  | Bil.Cast(Bil.SIGNED, _, _) -> Some(Ok(Data))
  | Bil.Cast(_, size, exp) ->
    if size = (Symbol_utils.arch_pointer_size_in_bytes project * 8) then type_of_exp exp state project else Some(Ok(Data)) (* TODO: There is probably a special case when 64bit addresses are converted to 32bit addresses here, which can yield pointers *)
  | Bil.Let(_) -> None
  | Bil.Unknown(_) -> None
  | Bil.Ite(if_, then_, else_) -> begin
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
      match (TypeInfo.compute_stack_offset state addr_exp project, type_of_exp value_exp state ~project) with
      | (Some(offset), Some(Ok(value))) when Size.in_bytes size = (Symbol_utils.arch_pointer_size_in_bytes project) ->
        let stack = Mem_region.add state.TypeInfo.stack value ~pos:offset ~size:(pointer_size_as_bitvector project) in
        { state with TypeInfo.stack = stack}
      | (Some(offset), Some(Ok(value))) when Size.in_bytes size <> (Symbol_utils.arch_pointer_size_in_bytes project) ->
        let stack = Mem_region.add state.TypeInfo.stack Register.Data ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with TypeInfo.stack = stack}
      | (Some(offset), Some(Error(_))) ->
        let stack = Mem_region.mark_error state.TypeInfo.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with TypeInfo.stack = stack}
      | (Some(offset), None) ->
        let stack = Mem_region.remove state.TypeInfo.stack ~pos:offset ~size:(Bitvector.of_int (Size.in_bytes size) ~width:(Symbol_utils.arch_pointer_size_in_bytes project)) in
        { state with TypeInfo.stack = stack}
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
            { state with TypeInfo.reg = Map.add state.TypeInfo.reg addr (Ok(Register.Pointer)) } (* TODO: there are some false positives here for indices in global data arrays, where the immediate is the pointer. Maybe remove all cases with potential false positives? *)
          | Bil.BinOp(Bil.PLUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.MINUS, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.AND, Bil.Var(addr), exp2)
          | Bil.BinOp(Bil.OR, Bil.Var(addr), exp2) ->
            if type_of_exp exp2 state project = Some(Ok(Register.Data)) then
              { state with TypeInfo.reg = Map.add state.TypeInfo.reg addr (Ok(Register.Pointer)) }
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
  if Def.lhs def = stack_register && Option.is_some state.TypeInfo.stack_offset then
    match Def.rhs def with
    | Bil.BinOp(Bil.PLUS, Bil.Var(var), Bil.Int(value)) ->
      if var = stack_register then
        TypeInfo.stack_offset_add state value
      else
        { state with TypeInfo.stack_offset = None }
    | Bil.BinOp(Bil.MINUS, Bil.Var(var), Bil.Int(value)) ->
      if var = stack_register then
        TypeInfo.stack_offset_add state (Bitvector.neg (Bitvector.signed value))
      else
        { state with TypeInfo.stack_offset = None }
    | _ -> { state with TypeInfo.stack_offset = None }
  else
    state

(* Remove any knowledge of the stack (except the stack_offset) and the registers (except stack and flag registers) from the state. *)
let keep_only_stack_offset state ~project =
  let empty_state = TypeInfo.empty() in
  { empty_state with
    TypeInfo.stack_offset = state.TypeInfo.stack_offset;
    TypeInfo.reg = TypeInfo.get_stack_pointer_and_flags project }

let update_state_def state def ~project =
  (* add all registers that are used as address registers in load/store expressions to the state *)
  let state = add_mem_address_registers state (Def.rhs def) project in
  let state = match type_of_exp (Def.rhs def) state project with
    | Some(value) ->
      let reg = Map.add state.TypeInfo.reg (Def.lhs def) value in
      { state with TypeInfo.reg = reg }
    | None -> (* We don't know the type of the new value *)
      let reg = Map.remove state.TypeInfo.reg (Def.lhs def) in
      { state with TypeInfo.reg = reg } in
  (* update stack offset and maybe write something to the stack *)
  let state = update_stack_offset state def ~project in
  let state = set_stack_elem state (Def.rhs def) ~project in
  state

let update_state_jmp state jmp ~project =
  match Jmp.kind jmp with
  | Call(call) -> begin match Call.target call with
      | Direct(tid) ->
        let program = Project.program project in
        let func = Term.find_exn sub_t program tid in
        if String.Set.mem (Cconv.parse_dyn_syms project) (Sub.name func) then
          let empty_state = TypeInfo.empty () in (* TODO: to preserve stack information we need to be sure that the callee does not write on the stack => needs pointer source tracking! *)
          { empty_state with
            TypeInfo.stack_offset = state.TypeInfo.stack_offset;
            TypeInfo.reg = Var.Map.filter_keys state.TypeInfo.reg ~f:(fun var -> Cconv.is_callee_saved var project) }
        else
          keep_only_stack_offset state project (* TODO: add interprocedural analysis here. *)
      | Indirect(_) -> keep_only_stack_offset state project (* TODO: when we have value tracking and interprocedural analysis, we can add indirect calls to the regular analysis. *)
    end
  | Int(_, _) -> (* TODO: We need stubs and/or interprocedural analysis here *)
    keep_only_stack_offset state project
  | Goto(Indirect(Bil.Var(var))) (* TODO: warn when jumping to something that is marked as data. *)
  | Ret(Indirect(Bil.Var(var))) ->
    let reg = Map.add state.TypeInfo.reg var (Ok(Register.Pointer)) in
    { state with TypeInfo.reg = reg }
  | Goto(_)
  | Ret(_)    -> state

(* This is public for unit test purposes. *)
let update_type_info block_elem state ~project =
  match block_elem with
  | `Def def -> update_state_def state def ~project
  | `Phi phi -> state (* We ignore phi terms for this analysis. *)
  | `Jmp jmp -> update_state_jmp state jmp ~project

(** updates a block analysis. *)
let update_block_analysis block register_state ~project =
  (* get all elements (Defs, Jumps, Phi-nodes) in the correct order *)
  let elements = Blk.elts block in
  let register_state = Seq.fold elements ~init:register_state ~f:(fun state element ->
      update_type_info element state ~project
    ) in
  TypeInfo.remove_virtual_registers register_state (* virtual registers should not be accessed outside of the block where they are defined. *)


let intraprocedural_fixpoint func ~project =
  let cfg = Sub.to_cfg func in
  (* default state for nodes *)
  let only_sp = { (TypeInfo.empty ()) with TypeInfo.reg = TypeInfo.get_stack_pointer_and_flags project } in
  (* Create a starting solution where only the first block of a function knows the stack_offset. *)
  let fn_start_state = TypeInfo.function_start_state project in
  let fn_start_block = Option.value_exn (Term.first blk_t func) in
  let fn_start_state = update_block_analysis fn_start_block fn_start_state ~project in
  let fn_start_node = Seq.find_exn (Graphs.Ir.nodes cfg) ~f:(fun node -> (Term.tid fn_start_block) = (Term.tid (Graphs.Ir.Node.label node))) in
  let empty = Map.empty Graphs.Ir.Node.comparator in
  let with_start_node = Map.add empty fn_start_node fn_start_state in
  let init = Graphlib.Std.Solution.create with_start_node only_sp in
  let equal = TypeInfo.equal in
  let merge = TypeInfo.merge in
  let f = (fun node state ->
      let block = Graphs.Ir.Node.label node in
      update_block_analysis block state ~project
    ) in
  Graphlib.Std.Graphlib.fixpoint (module Graphs.Ir) cfg ~steps:100 ~rev:false ~init:init ~equal:equal ~merge:merge ~f:f

(** Extract the starting state of a node. *)
let extract_start_state node ~cfg ~solution ~project =
  let predecessors = Graphs.Ir.Node.preds node cfg in
  if Seq.is_empty predecessors then
    TypeInfo.function_start_state project (* This should be the first block of a function. Maybe add a test for when there is more than one such block in a function? *)
  else
    let only_sp = { (TypeInfo.empty ()) with TypeInfo.reg = TypeInfo.get_stack_pointer_and_flags project } in
    Seq.fold predecessors ~init:only_sp ~f:(fun state node ->
        TypeInfo.merge state (Graphlib.Std.Solution.get solution node)
      )

(* TODO: remove or refactor to also print stack info. *)
let print_state state =
  print_string "Register: ";
  Map.iteri state.TypeInfo.reg ~f:(fun ~key:var ~data:reg ->
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
  let program = Project.program project in
  let program_with_tags = Term.map sub_t program ~f:(fun func ->
      let cfg = Sub.to_cfg func in
      let solution = intraprocedural_fixpoint func project in
      Seq.fold (Graphs.Ir.nodes cfg) ~init:func ~f:(fun func node ->
          let block = Graphs.Ir.Node.label node in
          let start_state = extract_start_state node cfg solution project in
          let tagged_block = Term.set_attr block type_info_tag start_state in
          Term.update blk_t func tagged_block
        )
    ) in
  Project.with_program project program_with_tags

let print_blocks_with_error_register ~project =
  let program = Project.program project in
  let functions = Term.enum sub_t program in
  Seq.iter functions ~f:(fun func ->
      let blocks = Term.enum blk_t func in
      Seq.iter blocks ~f:(fun block ->
          let start_state = Option.value_exn (Term.get_attr block type_info_tag) in
          let end_state = update_block_analysis block start_state project in
          if Map.exists end_state.TypeInfo.reg ~f:(fun register -> register = Error(())) then
            let () = print_string (Blk.pps () block) in
            print_state end_state
        )
    )
