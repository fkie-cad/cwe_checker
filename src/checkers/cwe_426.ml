open Bap.Std
open Core_kernel.Std

let name = "CWE426"
let version = "0.1"

let calls_privilege_changing_sub sub program symbols =
  List.exists symbols ~f:(fun s -> Symbol_utils.sub_calls_symbol program sub s)

let handle_sub sub program tid_map symbols =
  if calls_privilege_changing_sub sub program symbols then
    begin
      if Symbol_utils.sub_calls_symbol program sub "system" then
        Log_utils.warn "[%s] {%s} (Untrusted Search Path) sub %s at %s may be vulnerable to PATH manipulation."
          name
          version
          (Term.name sub)
          (Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map)
      else
        ()
    end
  else ()
    
let check_cwe program proj tid_map symbols =
  match symbols with
  | hd::[] ->
     Seq.iter (Term.enum sub_t program) ~f:(fun s -> handle_sub s program tid_map hd)
  | _ -> failwith "[CWE426] symbol_names not as expected"
