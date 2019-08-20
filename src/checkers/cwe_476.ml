open Core_kernel
open Bap.Std
open Log_utils

let name = "CWE476"
let version = "0.2"

(* Access type denotes whether a variable var gets accessed or the memory stored at
   address var gets accessed *)
type access_type = | Access of Bil.var | MemAccess of Bil.var | NoAccess

(* The union of two accesses is the higher access with MemAcces > Access > NoAccess *)
let union_access access1 access2 : access_type =
  match (access1, access2) with
  | (MemAccess(_), _) -> access1
  | (_, MemAccess(_))
  | (_, Access(_))    -> access2
  | _                 -> access1


(* union of three accesses for convenience *)
let union_access_triple access1 access2 access3 =
  union_access access1 access2
  |> union_access access3

(* the state contains a list of pairs of register names containing an unchecked
   return value and the term identifiers of the block where the unchecked
   return value was generated. *)
module State = struct
  type t = (Var.t * Tid.t) list

  (** adds var as a tainted register (with the taint source given by tid) *)
  let add state var tid =
    let state = List.Assoc.remove state ~equal:Var.(=) var in
    List.Assoc.add state ~equal:Var.(=) var tid

  (** returns Some(tid) if var is a tainted register, None otherwise *)
  let find state var =
    List.Assoc.find state ~equal:Var.(=) var

  (** returns the tid associated with a tainted register *)
  let find_exn state var =
    Option.value_exn (find state var)

  (** only remove the register var from the list of tainted registers *)
  let remove_var state var =
    List.Assoc.remove state ~equal:Var.(=) var

  (** filters out all registers from the state with the same tid *)
  let remove_tid state var =
    let tid = find_exn state var in
    List.filter state ~f:(fun (_, state_elem_tid) -> not (state_elem_tid = tid))

  (** two states are equal if they contain the same set of tainted registers*)
  let equal state1 state2 =
    (List.length state1) = (List.length state2) &&
    not (List.exists state1 ~f:(fun (var, _tid) -> Option.is_none (find state2 var) ))

  (** The union of two states is the union of the tainted registers*)
  let union state1 state2 =
    List.fold state2 ~init:state1 ~f:(fun state (var, tid) ->
        if Option.is_some (find state var) then
          state
        else
          (var, tid) :: state
      )

  (** remove virtual registers from the state (useful at the end of a block) *)
  let remove_virtual_registers state =
    List.filter state ~f:(fun (var, _tid) -> Var.is_physical var)

end

(* check whether an expression contains an unchecked value. *)
let rec contains_unchecked exp state : access_type =
  match exp with
  | Bil.Load(_mem, addr, _, _)->
    begin
      let acc = contains_unchecked addr state in
      match acc with
      | MemAccess(_) -> acc
      | Access(var) -> MemAccess(var)
      | NoAccess -> NoAccess
    end
  | Bil.Store(_mem, addr, val_expression, _,_) ->
    begin
      let acc = union_access (contains_unchecked addr state) (contains_unchecked val_expression state) in
      match acc with
      | MemAccess(_) -> acc
      | Access(var) -> MemAccess(var)
      | NoAccess -> NoAccess
    end
  | Bil.BinOp(_, exp1, exp2) -> union_access (contains_unchecked exp1 state) (contains_unchecked exp2 state)
  | Bil.UnOp(_, exp) -> contains_unchecked exp state
  | Bil.Var(var) ->
    begin
      match State.find state var with
      | Some(_) -> Access(var)
      | None -> NoAccess
    end
  | Bil.Int(_) -> NoAccess
  | Bil.Cast(_, _, exp) -> contains_unchecked exp state
  | Bil.Let(var, exp1, exp2) ->
    union_access_triple (contains_unchecked exp1 state) (contains_unchecked exp2 state) (contains_unchecked (Bil.var var) state)
  | Bil.Unknown(_) -> NoAccess
  | Bil.Ite(if_, then_, else_) ->
    union_access_triple (contains_unchecked if_ state) (contains_unchecked then_ state) (contains_unchecked else_ state)
  | Bil.Extract(_,_, exp) -> contains_unchecked exp state
  | Bil.Concat(exp1, exp2) -> union_access (contains_unchecked exp1 state) (contains_unchecked exp2 state)

(* If an formerly unchecked return value was checked then remove all registers pointing
   to the source of this return value from state. *)
let checks_value exp state : State.t =
  match exp with
  | Bil.Ite(if_, _then_, _else_) -> begin
      match contains_unchecked if_ state with
      | Access(var) ->
        (* We filter out all registers with the same generating tid, since we have checked
           the return value of this source *)
        State.remove_tid state var
      | MemAccess(_) (* This is a memory access before checking the return value, so do nothing here. *)
      | NoAccess -> state
    end
  | _ -> state

let append_to_hits (cwe_hits:Tid.t list ref) (tid:Tid.t) =
  match List.find cwe_hits.contents ~f:(fun elem -> elem = tid) with
  | Some(_) -> ()
  | None -> (cwe_hits := (tid :: cwe_hits.contents))

(** flags any access (not just memory access) from an unchecked source as a cwe_hit. *)
let flag_any_access exp state ~cwe_hits =
  match contains_unchecked exp state with
  | MemAccess(var) | Access(var) ->
    let tid = State.find_exn state var in
    append_to_hits cwe_hits tid;
    State.remove_tid state var
  | NoAccess -> state

(** flag all unchecked registers as cwe_hits, return empty state *)
let flag_all_unchecked_registers state ~cwe_hits =
  let () = List.iter state ~f:(fun (_var, tid) ->
      append_to_hits cwe_hits tid) in
  []

(** Updates the state depending on the def. If memory is accessed using an unchecked return value,
    then the access is added to the list of cwe_hits. *)
let update_state_def def state ~cwe_hits =
  let (lhs, rhs) = (Def.lhs def, Def.rhs def) in
  let state = checks_value rhs state in
  match contains_unchecked rhs state with
  | MemAccess(var) -> begin (* we found a case of unchecked return value *)
      let tid = State.find_exn state var in
      append_to_hits cwe_hits tid;
      State.remove_tid state var
    end
  | Access(var) -> (* taint the lhs as an unchecked return value *)
    let tid = State.find_exn state var in
    State.add state lhs tid
  | NoAccess -> (* no access to an unchecked return value in rhs. Since lhs is overwritten, it cannot be an unchecked return value anymore. *)
    State.remove_var state lhs

(** Taint the return registers of a function as unchecked return values. *)
let taint_return_registers func_tid state ~program ~block =
  let func = Term.find_exn sub_t program func_tid in
  let arguments = Term.enum arg_t func in
  (* Every return register is tainted as unchecked return value. *)
  Seq.fold arguments ~init:state ~f:(fun state arg ->
      match Bap.Std.Arg.intent arg with
      | None | Some(In) -> state
      | Some(Out) | Some(Both) ->
        let variable = match Bap.Std.Arg.rhs arg with
          | Bil.Var(var) -> var
          | _ -> failwith "[CWE476] Return register wasn't a register." in
        State.add state variable (Term.tid block)
    )

(** Updates the state depending on the jump. On a jump to a function from the function list
    taint all return registers as unchecked return values. *)
let update_state_jmp jmp state ~cwe_hits ~function_names ~program ~block ~strict_call_policy =
  (* first check the guard condition for unchecked access. Any normal access clears the access from being unchecked *)
  let condition_exp = Jmp.cond jmp in
  let state = begin
    match contains_unchecked condition_exp state with
    | Access(var) ->
      State.remove_tid state var
    | MemAccess(var) -> (* a memory access using an unchecked value is still an error *)
      let tid = State.find_exn state var in
      let () = append_to_hits cwe_hits tid in
      State.remove_tid state var
    | NoAccess -> state
  end in
  match Jmp.kind jmp with
  | Goto(Indirect(exp)) -> flag_any_access exp state ~cwe_hits
  | Goto(Direct(_)) -> state
  | Ret(_) -> if strict_call_policy then
      flag_all_unchecked_registers state ~cwe_hits
    else
      state
  | Int(_, _) -> flag_all_unchecked_registers state ~cwe_hits
  | Call(call) ->
    let state = match Call.return call with
      | Some(Indirect(exp)) -> flag_any_access exp state ~cwe_hits
      | _ -> state in
    let state = match Call.target call with
      | Indirect(exp) -> flag_any_access exp state ~cwe_hits
      | _ -> state in
    let state = match strict_call_policy with
      | true -> (* all unchecked registers get flagged as hits *)
        flag_all_unchecked_registers state ~cwe_hits
      | false -> (* we assume that the callee will check all remaining unchecked values *)
        [] in
    match Call.target call with
    | Indirect(_) -> state (* already handled above *)
    | Direct(tid) ->
      if List.exists function_names ~f:(fun elem -> String.(=) elem (Tid.name tid)) then
        taint_return_registers tid state ~program ~block
      else
        state

(** updates a block analysis.
    The strict call policy decides the behaviour on call and return instructions:
    strict: all unchecked values get flagged as cwe-hits
    non-strict: the state gets cleared, it is assumed that the target of the call/return
    instruction checks all remaining unchecked values. *)
let update_block_analysis block register_state ~cwe_hits ~function_names ~program ~strict_call_policy =
  let elements = Blk.elts block in
  let register_state = Seq.fold elements ~init:register_state ~f:(fun state element ->
      match element with
      | `Def def -> update_state_def def state ~cwe_hits
      | `Phi _phi -> state (* We ignore phi terms for this analysis. *)
      | `Jmp jmp -> update_state_jmp jmp state ~cwe_hits ~function_names ~program ~block ~strict_call_policy
    ) in
  State.remove_virtual_registers register_state (* virtual registers should not be accessed outside of the block where they are defined. *)

let print_hit tid ~sub ~function_names ~tid_map =
  let block = Option.value_exn (Term.find blk_t sub tid) in
  let jmps = Term.enum jmp_t block in
  let _ = Seq.find_exn jmps ~f:(fun jmp ->
      match Jmp.kind jmp with
      | Call(call) -> begin
          match Call.target call with
          | Direct(call_tid) -> Option.is_some (List.find function_names ~f:(fun fn_name ->
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

let check_cwe prog _proj tid_map symbol_names parameters =
  let symbols = match symbol_names with
    | hd :: _ -> hd
    | _ -> failwith "[CWE476] symbol_names not as expected" in
  let (strict_call_policy_string, max_steps_string) = match parameters with
    | par1 :: par2 :: _ -> (par1, par2)
    | _ -> failwith "[CWE476] parameters not as expected" in
  let strict_call_policy = match String.split strict_call_policy_string ~on:'=' with
    | "strict_call_policy" :: policy :: [] -> bool_of_string policy
    | _ -> failwith "[CWE476] parameters not as expected" in
  let max_steps = match String.split max_steps_string ~on:'=' with
    | "max_steps" :: num :: [] -> int_of_string num
    | _ -> failwith "[CWE476] parameters not as expected" in
  let function_names = List.map symbols ~f:(fun symb -> "@" ^ symb)  in
  let subfunctions = Term.enum sub_t prog in
  Seq.iter subfunctions ~f:(fun subfn ->
      let cfg = Sub.to_cfg subfn in
      let cwe_hits = ref [] in
      let empty = Map.empty (module Graphs.Ir.Node) in
      let init = Graphlib.Std.Solution.create empty [] in
      let equal = State.equal in
      let merge = State.union in
      let f = (fun node state ->
          let block = Graphs.Ir.Node.label node in
          update_block_analysis block state ~cwe_hits ~function_names ~program:prog ~strict_call_policy
        ) in
      let _ = Graphlib.Std.Graphlib.fixpoint (module Graphs.Ir) cfg ~steps:max_steps ~rev:false ~init:init ~equal:equal ~merge:merge ~f:f in
      List.iter (!cwe_hits) ~f:(fun hit -> print_hit hit ~sub:subfn ~function_names ~tid_map)
    )
