open Core_kernel
open Bap.Std

let translate_tid_to_assembler_address_string tid tid_map =
  match Tid.Map.find tid_map tid with
  | Some asm_addr -> Word.to_string asm_addr
  | _ -> "UNKNOWN"

let generate_tid_map prog =
  (object
    inherit [addr Tid.Map.t] Term.visitor
    method! enter_term _ t addrs = match Term.get_attr t address with
      | None -> addrs
      | Some addr -> Map.add_exn addrs ~key:(Term.tid t) ~data:addr
  end)#run prog Tid.Map.empty

let collect_addresses_sub sub =
  (object
    inherit (Tid.t list) Term.visitor
    method! enter_term _ t addrs = (Term.tid t) :: addrs 
  end)#run sub []
