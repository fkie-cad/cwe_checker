open Core_kernel
open Bap.Std
open Log_utils

let name = "CWE782"
let version = "0.1"

(*TODO: check if binary is setuid*)
let handle_sub sub program tid_map _symbols =
  if Symbol_utils.sub_calls_symbol program sub "ioctl" then
    begin
      let address = Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map in
      let symbol = Term.name sub in
      let description = sprintf
                          "(Exposed IOCTL with Insufficient Access Control) Program uses ioctl at %s (%s). Be sure to double check the program and the corresponding driver."
                          symbol
                          address in
      let cwe_warning = cwe_warning_factory name version ~addresses:[address] ~symbols:[symbol] description in
      collect_cwe_warning cwe_warning
    end
      else
        ()

let check_cwe program _proj tid_map symbols _ =
  Seq.iter (Term.enum sub_t program) ~f:(fun s -> handle_sub s program tid_map symbols)
