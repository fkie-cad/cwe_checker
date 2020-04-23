open Core_kernel
open Bap.Std


let tid_map = ref None


let translate_tid_to_assembler_address_string (tid : tid) (tid_map : word Tid.Map.t) : string =
  match Tid.Map.find tid_map tid with
  | Some asm_addr -> Word.to_string asm_addr
  | _ -> "UNKNOWN"

let generate_tid_map (prog : program term) : unit =
  tid_map := (object
    inherit [addr Tid.Map.t] Term.visitor
    method! enter_term _ t addrs = match Term.get_attr t address with
      | None -> addrs
      | Some addr -> Map.add_exn addrs ~key:(Term.tid t) ~data:addr
  end)#run prog Tid.Map.empty


let return_tid_map (program : program term) : word Tid.Map.t =
  match !tid_map with
  | None -> begin
      generate_tid_map program;
      !tid_map
    end
  | _ -> !tid_map


let tid_to_string tid = Bap.Std.Tid.name tid
