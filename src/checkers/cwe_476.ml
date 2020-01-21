open Core_kernel
open Bap.Std
open Log_utils

let name = "CWE476"
let version = "0.3"

(* TODO: This check is based on Mem_region, which does not support partial access yet.
   Thus partially written tainted values may be marked as error and thus the taint is falsely forgotten. *)


(** Each taint is denoted by the Tid of the basic block where it originated from.
    Each value can be tainted by different sources at the same time. *)
module Taint = Tid.Set

(** The state contains taint information for all registers and stack variables. *)
module State = struct
  type t = {
    register: Taint.t Var.Map.t;
    stack: Taint.t Mem_region.t;
  } [@@deriving bin_io, compare, sexp]

  (** Get an empty state without tainted values. *)
  let empty : t =
    { register = Var.Map.empty;
      stack = Mem_region.empty () }

  (** equality function for states *)
  let equal (state1: t) (state2: t) : Bool.t =
    let reg_equal = Var.Map.equal Taint.equal state1.register state2.register in
    let stack_equal = Mem_region.equal state1.stack state2.stack ~data_equal:Taint.equal in
    reg_equal && stack_equal

  (** set the taint of a register *)
  let set_register (state: t) (register: Var.t) (taint: Taint.t) : t =
    { state with register = Var.Map.set state.register ~key:register ~data: taint}

  (** return the taint of a register *)
  let find_register (state: t) (register: Var.t) : Taint.t Option.t =
    Var.Map.find state.register register

  (** only remove the register var from the list of tainted registers *)
  let remove_register (state: t) (register: Var.t) : t =
    { state with register = Var.Map.remove state.register register }

  (** set the taint of a stack element *)
  let set_stack (state: t) ~(pos: Bitvector.t) ~(size: Bitvector.t) (taint: Taint.t) : t =
    { state with stack = Mem_region.add state.stack taint ~pos ~size }

  (** get the taint from the stack
      TODO: Mem_region is currently unsound for only partially loaded values, which might lead to errors here. *)
  let find_stack (state: t) ~(pos: Bitvector.t) : Taint.t Option.t =
    match Mem_region.get state.stack pos with
    | Some(Ok(taint, _size)) -> Some(taint)
    | _ -> None

  (** remove a stack element *)
  let remove_stack (state: t) ~(pos: Bitvector.t) ~(size: Bitvector.t) : t =
    { state with stack = Mem_region.remove state.stack ~pos ~size}

  (** remove all Tids contained in the taint from all taints in the state *)
  let remove_taint (state: t) (taint_to_remove: Taint.t) : t =
    let register_list = Var.Map.to_alist state.register in
    let cleaned_register = List.fold register_list ~init:Var.Map.empty ~f:(fun cleaned_register (register, taint) ->
      let cleaned_taint = Tid.Set.diff taint taint_to_remove in
      if Tid.Set.is_empty cleaned_taint then
        cleaned_register
      else
        Var.Map.set cleaned_register ~key:register ~data:cleaned_taint
    ) in
    let cleaned_stack = Mem_region.map_data state.stack ~f:(fun taint ->
      Tid.Set.diff taint taint_to_remove
    ) in
    { register = cleaned_register;
      stack = cleaned_stack; }

  (** The union of two states is the union of all taints *)
  let union (state1: t) (state2: t) : t =
    let register = Var.Map.merge state1.register state2.register ~f:(fun ~key:_ values->
      match values with
      | `Both (taint1, taint2) -> Some (Taint.union taint1 taint2)
      | `Left taint | `Right taint -> Some taint
    ) in
    let stack = Mem_region.merge state1.stack state2.stack ~data_merge:(fun taint1 taint2 ->
      Some( Ok(Taint.union taint1 taint2) )
    ) in
    { register = register;
      stack = stack; }

  (** remove virtual register from the state (useful at the end of a block) *)
  let remove_virtual_register (state: t) : t =
    { state with register = Var.Map.filter_keys state.register ~f:(fun var -> Var.is_physical var) }

end


(** The stack info contains all necessary information to access stack variables. *)
module StackInfo = struct
  type t = {
    type_info: Type_inference.TypeInfo.t;
    sub_tid:  Tid.t;
    project: Project.t;
    strict_mem_policy: Bool.t;
  }

  (** If the expression denotes an address on the stack, return the address. *)
  let get_address (stack_info: t) (expression: Exp.t) : Bitvector.t Option.t =
    Type_inference.TypeInfo.compute_stack_offset stack_info.type_info expression ~sub_tid:stack_info.sub_tid ~project:stack_info.project

  (** Assemble a StackInfo.t object. *)
  let assemble (pointer_info_map: Type_inference.TypeInfo.t Tid.Map.t) (term_tid: Tid.t) ~(sub_tid: Tid.t) ~(project: Project.t) ~(strict_mem_policy: Bool.t) : t =
    { type_info = Tid.Map.find_exn pointer_info_map term_tid;
      sub_tid = sub_tid;
      project = project;
      strict_mem_policy = strict_mem_policy; }

  (**/**)
  (* assemble a mock StackInfo for unit tests *)
  let assemble_mock_info (mock_tid: Tid.t) (project: Project.t) : t =
    { type_info = { Type_inference.TypeInfo.stack = Mem_region.empty (); Type_inference.TypeInfo.reg = Var.Map.empty};
      sub_tid = mock_tid;
      project = project;
      strict_mem_policy = false; }
  (**/**)
end


(** append taint to the list of already found cwe_hits *)
let append_to_hits (cwe_hits:Taint.t ref) (taint: Taint.t) : unit =
  cwe_hits := Taint.union !cwe_hits taint


(** Check whether an expression contains a tainted value.
    Memory accesses through tainted values are added to cwe_hits, but the Tids are not removed from the state. *)
let rec contains_taint (exp: Exp.t) (state: State.t) ~(cwe_hits: Taint.t ref) ~(stack: StackInfo.t) : Taint.t =
  match exp with
  | Bil.Load(_mem, addr, _endian, _size)->
    begin
      let access_taint = contains_taint addr state ~cwe_hits ~stack in
      let () = if Taint.is_empty access_taint = false then append_to_hits cwe_hits access_taint in
      match StackInfo.get_address stack addr with
      | Some(stack_offset) -> Option.value (State.find_stack state ~pos:stack_offset) ~default:Taint.empty
      | None -> Taint.empty
    end
  | Bil.Store(_mem, addr, val_expression, _,_) ->
    begin
      let access_taint = contains_taint addr state ~cwe_hits ~stack in
      let value_taint = contains_taint val_expression state ~cwe_hits ~stack in
      let () = if Taint.is_empty access_taint = false then append_to_hits cwe_hits access_taint in
      match StackInfo.get_address stack addr with
      | Some(_) -> Taint.empty
      | None ->
          let () = if stack.strict_mem_policy && (Taint.is_empty value_taint = false) then append_to_hits cwe_hits value_taint in
          Taint.empty
    end
  | Bil.BinOp(Bil.XOR, Bil.Var(var1), Bil.Var(var2)) when var1 = var2 -> Taint.empty (* standard assembly shortcut for setting a register to NULL *)
  | Bil.BinOp(_, exp1, exp2) -> Taint.union (contains_taint exp1 state ~cwe_hits ~stack) (contains_taint exp2 state ~cwe_hits ~stack)
  | Bil.UnOp(_, exp) -> contains_taint exp state ~cwe_hits ~stack
  | Bil.Var(var) -> Option.value (State.find_register state var) ~default:Taint.empty
  | Bil.Int(_) -> Taint.empty
  | Bil.Cast(_, _, exp) -> contains_taint exp state ~cwe_hits ~stack
  | Bil.Let(var, exp1, exp2) ->
      Taint.union_list (
        (contains_taint exp1 state ~cwe_hits ~stack)
        :: (contains_taint exp2 state ~cwe_hits ~stack)
        :: (contains_taint (Bil.var var) state ~cwe_hits ~stack) :: [])
  | Bil.Unknown(_) -> Taint.empty
  | Bil.Ite(if_, then_, else_) ->
      Taint.union_list (
        (contains_taint if_ state ~cwe_hits ~stack)
        :: (contains_taint then_ state ~cwe_hits ~stack)
        :: (contains_taint else_ state ~cwe_hits ~stack) :: [])
  | Bil.Extract(_,_, exp) -> contains_taint exp state ~cwe_hits ~stack
  | Bil.Concat(exp1, exp2) -> Taint.union (contains_taint exp1 state ~cwe_hits ~stack) (contains_taint exp2 state ~cwe_hits ~stack)


(** Parse an expression for memory accesses through tainted values and taint contained in the value itself.
    All memory accesses except for loading/storing values from/to the stack get flagged as cwe_hits.
    Returns the taint of the expression and the new state, with the Tids of new cwe_hits removed from both. *)
let parse_taint_of_exp (exp: Exp.t) (state: State.t) ~(cwe_hits: Taint.t ref) ~(stack: StackInfo.t) : Taint.t * State.t =
  let hits_to_clean : Taint.t ref = ref Taint.empty in
  let unchecked_taint = contains_taint exp state ~cwe_hits:hits_to_clean ~stack in
  let () = append_to_hits cwe_hits !hits_to_clean in
  let state = State.remove_taint state !hits_to_clean in
  let unchecked_taint = Taint.diff unchecked_taint !hits_to_clean in
  (unchecked_taint, state)


(** If an formerly unchecked return value was checked then remove all registers pointing
    to the source of this return value from state. *)
let checks_value (exp: Exp.t) (state: State.t) ~(cwe_hits: Taint.t ref) ~(stack: StackInfo.t) : State.t =
  match exp with
  | Bil.Ite(if_, _then_, _else_) -> begin
      let (taint_to_remove, state) = parse_taint_of_exp if_ state ~cwe_hits ~stack in
      if Taint.is_empty taint_to_remove = false then
        State.remove_taint state taint_to_remove
      else
        state
    end
  | _ -> state


(** flags any access (not just memory access) from an unchecked source as a cwe_hit. *)
let flag_any_access (exp: Exp.t) (state: State.t) ~(cwe_hits: Taint.t ref) ~(stack: StackInfo.t) : State.t=
  let (taint_to_flag, state) = parse_taint_of_exp exp state ~cwe_hits ~stack in
  let () = append_to_hits cwe_hits taint_to_flag in
  State.remove_taint state taint_to_flag


(** flag all unchecked registers and stack variables that may be used as return values.
    That means stack variables above the return pointer get flagged,
    but variables below the return pointer are treated as local variables and do not get flagged.
    Return empty state *)
let flag_unchecked_return_values (state: State.t) ~(cwe_hits: Taint.t ref) ~(project: Project.t) : State.t =
  let taint_to_flag = Var.Map.fold state.register ~init:Taint.empty ~f:(fun ~key ~data taint_accum ->
    if Cconv.is_return_register key project then
      Taint.union taint_accum data
    else
      taint_accum
  ) in
  let taint_to_flag = List.fold (Mem_region.list_data_pos state.stack) ~init:taint_to_flag ~f:(fun taint_accum (position_unsigned, taint_value) ->
    let position = Bitvector.to_int_exn (Bitvector.signed position_unsigned) in
    if position >= 0 then
      Taint.union taint_accum taint_value
    else
      taint_accum
  ) in
  let () = append_to_hits cwe_hits taint_to_flag in
  State.empty


(** flag all register taints as cwe_hits, but not taints that are only contained in stack variables *)
let flag_register_taints (state: State.t) ~(cwe_hits: Taint.t ref) : State.t =
  let taint_to_flag = List.fold (Var.Map.data state.register) ~init: Taint.empty ~f:(fun taint_accum register_taint ->
    Taint.union taint_accum register_taint
  ) in
  let () = append_to_hits cwe_hits taint_to_flag in
  State.remove_taint state taint_to_flag


(** Flag all possible parameter register as cwe_hits. These registers may be input values to an extern function call.
    This can lead to false positives if a function does not use all of these registers for argument passing. *)
let flag_parameter_register (state: State.t) ~(cwe_hits: Taint.t ref) ~(project: Project.t) : State.t =
  let taint_to_flag = Var.Map.fold state.register ~init:Taint.empty ~f:(fun ~key ~data taint_accum ->
    if Cconv.is_parameter_register key project then
      Taint.union taint_accum data
    else
      taint_accum
  ) in
  let () = append_to_hits cwe_hits taint_to_flag in
  State.remove_taint state taint_to_flag


(** Remove the taint of non-callee-saved register (without flagging them).
    For taints in parameter register we assume that they are checked by the callee, thus we also remove the corresponding Tids from the state. *)
let untaint_non_callee_saved_register (state: State.t) ~(project: Project.t) : State.t =
  let taint_to_remove = Var.Map.fold state.register ~init:Taint.empty ~f:(fun ~key ~data taint_accum ->
    if Cconv.is_callee_saved key project then
      taint_accum
    else
      Taint.union taint_accum data
  ) in
  let state = State.remove_taint state taint_to_remove in
  Var.Map.fold state.register ~init:state ~f:(fun ~key ~data:_ state ->
    if Cconv.is_callee_saved key project then
      state
    else
      State.remove_register state key
  )


(** If the expression is a store onto a stack variable, write the corresponding taint to the stack. *)
let update_stack_on_stores (exp: Exp.t) (state: State.t) ~(stack: StackInfo.t) : State.t =
  let pointer_size = Symbol_utils.arch_pointer_size_in_bytes stack.project in
  match exp with
  | Bil.Store(_mem, address_exp, value, _endian, size) -> begin
      let value_taint = contains_taint value state ~cwe_hits:(ref Taint.empty) ~stack in
      match StackInfo.get_address stack address_exp with
      | Some(address) ->
          if Taint.is_empty value_taint then
            State.remove_stack state ~pos:address ~size:(Bitvector.of_int (Size.in_bytes size) ~width:pointer_size)
          else
            State.set_stack state value_taint ~pos:address ~size:(Bitvector.of_int (Size.in_bytes size) ~width:pointer_size)
      | None -> state
    end
  | _ -> state


(** Updates the state depending on the def. If memory is accessed using an unchecked return value,
    then the access is added to the list of cwe_hits. *)
let update_state_def (def: Def.t) (state: State.t) ~(cwe_hits: Taint.t ref) ~(stack: StackInfo.t) : State.t =
  let (lhs, rhs) = (Def.lhs def, Def.rhs def) in
  let state = checks_value rhs state ~cwe_hits ~stack in
  let (rhs_taint, state) = parse_taint_of_exp rhs state ~cwe_hits ~stack in
  let state =
    if Taint.is_empty rhs_taint then
      State.remove_register state lhs
    else
      State.set_register state lhs rhs_taint in
  update_stack_on_stores rhs state ~stack


(** Taint the return registers of a function as unchecked return values. *)
let taint_return_registers (func_tid: Tid.t) (state: State.t) ~(project: Project.t) ~(block: Blk.t) : State.t =
  let func = Term.find_exn sub_t (Project.program project) func_tid in
  let arguments = Term.enum arg_t func in
  (* Every return register is tainted as unchecked return value. *)
  Seq.fold arguments ~init:state ~f:(fun state arg ->
      match Bap.Std.Arg.intent arg with
      | None | Some(In) -> state
      | Some(Out) | Some(Both) ->
        let variable = match Bap.Std.Arg.rhs arg with
          | Bil.Var(var) -> var
          | _ -> failwith "[CWE476] Return register wasn't a register." in
        State.set_register state variable (Taint.add Taint.empty (Term.tid block))
    )

(** Updates the state depending on the jump. On a jump to a function from the function list
    taint all return registers as unchecked return values. *)
let update_state_jmp
      (jmp: Jmp.t)
      (state: State.t)
      ~(cwe_hits: Taint.t ref)
      ~(malloc_like_functions: String.t List.t)
      ~(extern_functions: String.Set.t)
      ~(stack: StackInfo.t)
      ~(block: Blk.t)
      ~(strict_call_policy: Bool.t) : State.t =
  (* first check the guard condition for unchecked access. Any normal access clears the access from being unchecked *)
  let condition_exp = Jmp.cond jmp in
  let state = begin
    let (condition_taint, state) = parse_taint_of_exp condition_exp state ~cwe_hits ~stack in
    if Taint.is_empty condition_taint then
      state
    else
      State.remove_taint state condition_taint
  end in
  match Jmp.kind jmp with
  | Goto(Indirect(exp)) -> flag_any_access exp state ~cwe_hits ~stack
  | Goto(Direct(_)) -> state
  | Ret(_) -> if strict_call_policy then
      flag_unchecked_return_values state ~cwe_hits ~project:stack.project
    else
      state
  | Int(_, _) -> flag_register_taints state ~cwe_hits
  | Call(call) ->
      (* flag tainted values in the call and return expressions of indirect calls *)
      let state = match Call.return call with
        | Some(Indirect(exp)) -> flag_any_access exp state ~cwe_hits ~stack
        | _ -> state in
      let state =  begin match Call.target call with
        | Indirect(exp) -> flag_any_access exp state ~cwe_hits ~stack
        | _ -> state end in
      (* flag tainted values in the parameter registers (if strict_call_policy is set to true)*)
      let state = match (Call.target call, strict_call_policy) with
        | (Indirect(_), false)
        | (Direct(_), false) -> state
        | (Indirect(_), true) -> flag_parameter_register state ~cwe_hits ~project:stack.project (* TODO: indirect calls are handled as extern calls right now. Change that *)
        | (Direct(tid), true) ->
            let sub = Term.find_exn sub_t (Project.program stack.project) tid in
            if Set.mem extern_functions (Sub.name sub) then
              flag_parameter_register state ~cwe_hits ~project:stack.project
            else (* flag all registers for intern calls, as these do not necessarily adhere to any calling convention *)
              flag_register_taints state ~cwe_hits
      in
      (* remove the taint of non-callee-saved registers *)
      let state = match Call.target call with
        | Direct(tid) ->
            let sub = Term.find_exn sub_t (Project.program stack.project) tid in
            if Set.mem extern_functions (Sub.name sub) then
              untaint_non_callee_saved_register state ~project:stack.project
            else (* we untaint all registers for internal function calls, as these do not necessarily adhere to any calling convention *)
              { state with register = Var.Map.empty }
        | Indirect(_) -> (* we treat all indirect calls as extern function calls, since we cannot handle indirect calls properly yet *)
            untaint_non_callee_saved_register state ~project:stack.project
      in
      (* introduce new taint for the return values of malloc_like_functions *)
      match Call.target call with
      | Indirect(_) -> state
      | Direct(tid) ->
          if List.exists malloc_like_functions ~f:(fun elem -> String.(=) elem (Tid.name tid)) then
            taint_return_registers tid state ~project:stack.project ~block
          else
            state


(** updates a block analysis.
    The strict call policy decides the behaviour on call and return instructions:
    strict: unchecked values in registers get flagged as cwe_hits
    non-strict: unchecked values in registers get marked as checked. It is assumed that the callee checks these values. *)
let update_block_analysis
      (block: Blk.t)
      (state: State.t)
      ~(cwe_hits: Taint.t ref)
      ~(malloc_like_functions: String.t List.t)
      ~(extern_functions: String.Set.t)
      ~(sub_tid: Tid.t)
      ~(project: Project.t)
      ~(strict_call_policy: Bool.t)
      ~(strict_mem_policy: Bool.t)  : State.t =
  let elements = Blk.elts block in
  let type_info_map = Type_inference.get_type_info_of_block ~project block ~sub_tid in
  let state = Seq.fold elements ~init:state ~f:(fun state element ->
      match element with
      | `Def def ->
          let stack = StackInfo.assemble type_info_map (Term.tid def) ~sub_tid ~project ~strict_mem_policy in
          update_state_def def state ~cwe_hits ~stack
      | `Phi _phi -> state (* We ignore phi terms for this analysis. *)
      | `Jmp jmp ->
          let stack = StackInfo.assemble type_info_map (Term.tid jmp) ~sub_tid ~project ~strict_mem_policy in
          update_state_jmp jmp state ~cwe_hits ~malloc_like_functions ~extern_functions ~stack ~block ~strict_call_policy
    ) in
  State.remove_virtual_register state (* virtual registers should not be accessed outside of the block where they are defined. *)


(** print a cwe_hit to the log *)
let print_hit (tid: Tid.t) ~(sub: Sub.t) ~(malloc_like_functions: String.t List.t) ~(tid_map: Word.t Tid.Map.t) : unit =
  let block = Option.value_exn (Term.find blk_t sub tid) in
  let jmps = Term.enum jmp_t block in
  let _ = Seq.find_exn jmps ~f:(fun jmp ->
    match Jmp.kind jmp with
    | Call(call) -> begin
        match Call.target call with
        | Direct(call_tid) -> Option.is_some (List.find malloc_like_functions ~f:(fun fn_name ->
          if fn_name = (Tid.name call_tid) then
            begin
              let address = Address_translation.translate_tid_to_assembler_address_string tid tid_map in
              let tids = [Address_translation.tid_to_string tid] in
              let description = sprintf
                                  "(NULL Pointer Dereference) There is no check if the return value is NULL at %s (%s)."
                                  address
                                  fn_name in
              let cwe_warning = cwe_warning_factory
                                  name
                                  version
                                  ~addresses:[address]
                                  ~tids:tids
                                  ~symbols:[fn_name]
                                  description in
              collect_cwe_warning cwe_warning;
              true
            end else
            false
        ))
        | _ -> false
      end
    | _ -> false
  ) in ()


let check_cwe (_prog: Program.t) (project: Project.t) (tid_map: Word.t Tid.Map.t) (symbol_names: String.t List.t List.t) (parameters: String.t List.t) =
  let symbols = match symbol_names with
    | hd :: _ -> hd
    | _ -> failwith "[CWE476] symbol_names not as expected" in
  let (strict_call_policy_string, strict_mem_policy_string, max_steps_string) = match parameters with
    | par1 :: par2 :: par3 :: _ -> (par1, par2, par3)
    | _ -> failwith "[CWE476] parameters not as expected" in
  let strict_call_policy = match String.split strict_call_policy_string ~on:'=' with
    | "strict_call_policy" :: policy :: [] -> bool_of_string policy
    | _ -> failwith "[CWE476] parameters not as expected" in
  let strict_mem_policy = match String.split strict_mem_policy_string ~on:'=' with
    | "strict_memory_policy" :: policy :: [] -> bool_of_string policy
    | _ -> failwith "[CWE476] parameters not as expected" in
  let max_steps = match String.split max_steps_string ~on:'=' with
    | "max_steps" :: num :: [] -> int_of_string num
    | _ -> failwith "[CWE476] parameters not as expected" in
  let malloc_like_functions = List.map symbols ~f:(fun symb -> "@" ^ symb)  in
  let extern_functions = Cconv.parse_dyn_syms project in
  (* run the pointer inference analysis. TODO: This should be done somewhere else as this analysis will be needed in more than one check! *)
  let project = Type_inference.compute_pointer_register project in
  let subfunctions = Term.enum sub_t (Project.program project) in
  Seq.iter subfunctions ~f:(fun subfn ->
      let cfg = Sub.to_cfg subfn in
      let cwe_hits = ref Taint.empty in
      let empty = Map.empty (module Graphs.Ir.Node) in
      let init = Graphlib.Std.Solution.create empty State.empty in
      let equal = State.equal in
      let merge = State.union in
      let f = (fun node state ->
          let block = Graphs.Ir.Node.label node in
          update_block_analysis block state ~cwe_hits ~malloc_like_functions ~extern_functions ~sub_tid:(Term.tid subfn) ~project ~strict_call_policy ~strict_mem_policy
        ) in
      let _ = Graphlib.Std.Graphlib.fixpoint (module Graphs.Ir) cfg ~steps:max_steps ~rev:false ~init:init ~equal:equal ~merge:merge ~f:f in
      Tid.Set.iter (!cwe_hits) ~f:(fun hit -> print_hit hit ~sub:subfn ~malloc_like_functions ~tid_map)
  )

(**/**)
(* Functions made public for unit tests *)
module Private = struct
  module StackInfo = StackInfo
  module Taint = Taint
  module State = State
  let flag_unchecked_return_values = flag_unchecked_return_values
  let flag_register_taints = flag_register_taints
  let flag_parameter_register = flag_parameter_register
  let untaint_non_callee_saved_register = untaint_non_callee_saved_register
end
