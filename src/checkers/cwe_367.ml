open Core_kernel
open Bap.Std
open Log_utils

let name = "CWE367"
let version = "0.1"

let get_calls_to_symbol symbol_name callsites program =
  match Symbol_utils.find_symbol program symbol_name with
      | Some symbol ->
        begin
          Seq.filter callsites ~f:(fun callsite -> match Jmp.kind callsite with
            | Goto _ | Ret _ | Int (_,_) -> false
            | Call destination -> match Call.target destination with
              | Direct addr -> Tid.(=) addr symbol
              | _ -> false)
        end
      | None -> Seq.empty

let get_blk_tid_of_tid sub tid =
 let blk = Seq.find (Term.enum blk_t sub) ~f:(
      fun b ->
      match Term.last jmp_t b with
      | Some last_term -> Tid.(=) tid (Term.tid last_term)
      | None -> false) in
 match blk with
 | Some b -> Term.tid b
 | _ -> assert(false)

let is_reachable sub source sink =
  let cfg = Sub.to_graph sub in
  let source_tid = Term.tid source in
  let sink_tid = Term.tid sink in
  let source_blk = get_blk_tid_of_tid sub source_tid in
  let sink_blk = get_blk_tid_of_tid sub sink_tid in
  Graphlib.Std.Graphlib.is_reachable (module Graphs.Tid) cfg source_blk sink_blk

let handle_sub sub program tid_map _symbols source_sink_pair =
  match source_sink_pair with
  | [source;sink;] -> begin
      if (Symbol_utils.sub_calls_symbol program sub source) && (Symbol_utils.sub_calls_symbol program sub sink) then
        begin
          let calls = Symbol_utils.get_direct_callsites_of_sub sub in
          let source_calls = get_calls_to_symbol source calls program in
          let sink_calls = get_calls_to_symbol sink calls program in
          Seq.iter source_calls ~f:(fun source_call ->
              Seq.iter sink_calls ~f:(fun sink_call ->
                  if is_reachable sub source_call sink_call then
                    let address = (Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map) in
                    let tid = Address_translation.tid_to_string @@ Term.tid sub in
                    let symbol = (Term.name sub) in
                    let other = [["source"; source]; ["sink"; sink]] in
                    let description = sprintf 
                     "(Time-of-check Time-of-use Race Condition) %s is reachable from %s at %s (%s). This could lead to a TOCTOU."
                      sink
                      source
                      address
                      symbol in
                    let cwe_warning = cwe_warning_factory
                                        name
                                        version
                                        description
                                        ~other:other
                                        ~addresses:[address]
                                        ~tids:[tid]
                                        ~symbols:[symbol] in
                    collect_cwe_warning cwe_warning
                  else
                    ()))
        end
      else
        ()
    end
  | _ -> ()

let check_cwe program _proj tid_map symbol_pairs _ =
  List.iter symbol_pairs ~f:(fun current_pair -> 
  let symbols = Symbol_utils.build_symbols current_pair in
  Seq.iter (Term.enum sub_t program) ~f:(fun s -> handle_sub s program tid_map symbols current_pair))
