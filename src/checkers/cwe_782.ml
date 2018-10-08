open Bap.Std
open Core_kernel.Std

let name = "CWE782"
let version = "0.1"

(*TODO: check if binary is setuid*)
let handle_sub sub program tid_map symbols =
      if Symbol_utils.sub_calls_symbol program sub "ioctl" then
        Log_utils.warn "[%s] {%s} (Exposed IOCTL with Insufficient Access Control) Program uses ioctl at %s (%s). Be sure to double check the program and the corresponding driver."
          name
          version
          (Term.name sub)
          (Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map)
      else
        ()
    
let check_cwe program proj tid_map symbols =
  Seq.iter (Term.enum sub_t program) ~f:(fun s -> handle_sub s program tid_map symbols)
