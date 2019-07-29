open Core_kernel
open Bap.Std
open Symbol_utils
open Log_utils

let name = "CWE467"
let version = "0.1"

let get_pointer_size arch =
  Size.in_bytes @@ Arch.addr_size arch

let check_input_is_pointer_size proj _prog _sub blk jmp tid_map symbols =
  Seq.iter (Term.enum def_t blk) ~f:(fun d ->  match Exp.eval @@ Def.rhs d with
      | Imm w ->
        begin
        try
          if get_pointer_size (Project.arch proj) = (Word.to_int_exn w) then
            begin
              let address = Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map in
              let symbol = Symbol_utils.get_symbol_name_from_jmp jmp symbols in
              let description = sprintf
                                  "(Use of sizeof on a Pointer Type) sizeof on pointer at %s (%s)."
                                  address
                                  symbol in
              let cwe_warning = cwe_warning_factory name version ~addresses:[address] ~symbols:[symbol] description in
              collect_cwe_warning cwe_warning
            end
        with _ -> Log_utils.error "Caught exception in module [CWE467]."
      end
      | _ -> ())


let check_cwe prog proj tid_map symbol_names _ =
  match symbol_names with
  | hd::[] ->
     let symbols = Symbol_utils.build_symbols hd prog in
     let calls = call_finder#run prog [] in
     let relevant_calls = filter_calls_to_symbols calls symbols in
     check_calls relevant_calls prog proj tid_map symbols check_input_is_pointer_size
  | _ -> failwith "[CWE467] symbol_names not as expected"
