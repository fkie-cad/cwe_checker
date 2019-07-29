open Core_kernel
open Bap.Std
open Log_utils

let name = "CWE426"
let version = "0.1"

let calls_privilege_changing_sub sub program symbols =
  List.exists symbols ~f:(fun s -> Symbol_utils.sub_calls_symbol program sub s)

let handle_sub sub program tid_map symbols =
  if calls_privilege_changing_sub sub program symbols then
    begin
      if Symbol_utils.sub_calls_symbol program sub "system" then
        let symbol = Term.name sub in
        let address = Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map in
        let description = sprintf "(Untrusted Search Path) sub %s at %s may be vulnerable to PATH manipulation."
          symbol
          address in
        let cwe_warning = cwe_warning_factory name version ~addresses:[address] ~symbols:[symbol] description in
        collect_cwe_warning cwe_warning
      else
        ()
    end
  else ()

let check_cwe program _proj tid_map symbols _ =
  match symbols with
  | hd::[] ->
     Seq.iter (Term.enum sub_t program) ~f:(fun s -> handle_sub s program tid_map hd)
  | _ -> failwith "[CWE426] symbol_names not as expected"
