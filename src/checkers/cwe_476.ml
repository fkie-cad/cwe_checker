open Core_kernel.Std
open Bap.Std
open Symbol_utils

let name = "CWE476"
let version = "0.1"

let find_blk_tid_in_sub blk_tid sub =
  Seq.find (Term.enum blk_t sub) ~f:(fun b -> (Term.tid b) = blk_tid)

let get_jmps blk = Seq.filter (Blk.elts blk) ~f:(fun elt -> match elt with
          | `Phi phi -> false
          | `Def def -> false
          | `Jmp jmp -> true )
                   |> Seq.map ~f:(fun j -> match j with
                       | `Jmp jmp -> jmp
                       | _ -> assert(false))

let jmp_cond_checks_zf jmp =
  let e = Jmp.cond jmp in
  (Exp.to_string e) = "~ZF" || (Exp.to_string e) = "ZF"

(* Check if next block contains when zf = 0 goto, if not then there is a chance that this yields a null pointer deref *)
let check_null_pointer proj prog sub blk jmp tid_map symbols =
  Seq.iter (Graphs.Tid.Node.succs (Term.tid blk) (Sub.to_graph sub)) ~f:(
    fun next_blk -> match find_blk_tid_in_sub next_blk sub with
      | Some b -> begin
          (* ToDo: Check if there is a definition of ZF = 0 *)
          let jmps = get_jmps b in
          match Seq.find jmps ~f:jmp_cond_checks_zf with
          | Some _ -> ()
          | None -> Log_utils.warn "[%s] {%s} (NULL Pointer Dereference) There is no check if the return value is NULL at %s (%s)."
                      name
                      version
                      (Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map)
                      (Symbol_utils.get_symbol_name_from_jmp jmp symbols)
          end
      | _ -> assert(false))

let check_cwe prog proj tid_map symbol_names =
  let symbols = Symbol_utils.build_symbols symbol_names prog in 
  let calls = call_finder#run prog [] in
  let relevant_calls = filter_calls_to_symbols calls symbols in
  check_calls relevant_calls prog proj tid_map symbols check_null_pointer
