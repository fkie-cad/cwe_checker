open Bap.Std
open Core_kernel.Std

let name = "CWE676"
let version = "0.1"

let get_call_to_target cg callee target =
   Term.enum blk_t callee |>
   Seq.concat_map ~f:(fun blk ->
       Term.enum jmp_t blk |> Seq.filter_map ~f:(fun j ->
           match Jmp.kind j with
           | Goto _ | Ret _ | Int (_,_) -> None
           | Call dst -> match Call.target dst with
             | Direct tid when tid = (Term.tid target) ->
               Some (Term.name callee, Term.tid blk, Term.name target)
             | _ -> None))

let get_calls_to_symbols cg subfunctions symbols =
  (Seq.concat_map subfunctions ~f:(fun subfunction ->
      Seq.concat_map symbols ~f:(fun symbol -> get_call_to_target cg subfunction symbol)))

(* FIXME: refactor variable names *)
let print_calls calls ~tid_map =
   Seq.iter calls ~f:(fun call -> match call with
      | (a, b, c) -> Log_utils.warn
                       "[%s] {%s} (Use of Potentially Dangerous Function) %s (%s) -> %s."
                       name
                       version
                       a
                       (Address_translation.translate_tid_to_assembler_address_string b tid_map)
                       c)

let resolve_symbols prog symbols =
  Term.enum sub_t prog |>
    Seq.filter ~f:(fun s -> List.exists ~f:(fun x -> x = Sub.name s) symbols)


let check_cwe prog proj tid_map symbol_names _ =
  match symbol_names with
  | hd::[] ->
     let subfunctions = Term.enum sub_t prog in
     let cg = Program.to_graph prog in
     get_calls_to_symbols cg subfunctions (resolve_symbols prog hd)
     |> print_calls ~tid_map:tid_map
  | _ -> failwith "[CWE676] symbol_names not as expected"
