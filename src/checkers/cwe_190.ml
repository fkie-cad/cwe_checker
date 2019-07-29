open Core_kernel
open Bap.Std
open Symbol_utils
open Log_utils

let name = "CWE190"
let version = "0.1"

let collect_muliplications = Exp.fold ~init:0 (object
    inherit [Int.t] Exp.visitor
    method! enter_binop op _o1 _o2 binops = match op with
      | Bil.TIMES | Bil.LSHIFT -> binops + 1
      | _ -> binops
end)

let contains_multiplication d =
  let rhs = Def.rhs d in
  let binops = collect_muliplications rhs in
  binops > 0

let check_multiplication_before_symbol _proj _prog _sub blk jmp tid_map symbols =
  Seq.iter (Term.enum def_t blk)
    ~f:(fun d -> if contains_multiplication d then
                   let description = "(Integer Overflow or Wraparound) Potential overflow due to multiplication" in
                   let addresses = [(Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map)] in
                   let symbols = [(Symbol_utils.get_symbol_name_from_jmp jmp symbols)] in
                   let cwe_warning = cwe_warning_factory name version description ~addresses ~symbols in
                   collect_cwe_warning cwe_warning)

let check_cwe prog proj tid_map symbol_names _ =
  match symbol_names with
  | hd::[] ->
   let symbols = Symbol_utils.build_symbols hd prog in
   let calls = call_finder#run prog [] in
   let relevant_calls = filter_calls_to_symbols calls symbols in
   check_calls relevant_calls prog proj tid_map symbols check_multiplication_before_symbol
  | _ -> failwith "[CWE190] symbol_names not as expected"
