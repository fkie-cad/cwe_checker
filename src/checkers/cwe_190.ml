open Core_kernel.Std
open Bap.Std
open Symbol_utils

let name = "CWE190"
let version = "0.1"

let collect_muliplications = Exp.fold ~init:0 (object
    inherit [Int.t] Exp.visitor
    method! enter_binop op o1 o2 binops = match op with
      | Bil.TIMES | Bil.LSHIFT -> binops + 1
      | _ -> binops
end)

let contains_multiplication d =
  let rhs = Def.rhs d in
  let binops = collect_muliplications rhs in
  binops > 0

let check_multiplication_before_symbol proj prog sub blk jmp tid_map symbols =
  Seq.iter (Term.enum def_t blk)
    ~f:(fun d -> if contains_multiplication d then
                   Log_utils.warn
                     "[%s] {%s} (Integer Overflow or Wraparound) Potential overflow due to multiplication %s (%s)."
                     name
                     version
                     (Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map)
                     (Symbol_utils.get_symbol_name_from_jmp jmp symbols))

let check_cwe prog proj tid_map symbol_names =
   let symbols = Symbol_utils.build_symbols symbol_names prog in 
   let calls = call_finder#run prog [] in
   let relevant_calls = filter_calls_to_symbols calls symbols in
   check_calls relevant_calls prog proj tid_map symbols check_multiplication_before_symbol
