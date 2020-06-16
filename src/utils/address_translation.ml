open Core_kernel
open Bap.Std


let translate_tid_to_assembler_address_string (tid : tid) (tid_map : word Tid.Map.t) : string =
  match Tid.Map.find tid_map tid with
  | Some asm_addr -> Word.to_string asm_addr
  | _ -> "UNKNOWN"


let generate_tid_map (prog : program term) : word Tid.Map.t =

  let last_addr = ref None in

  (object
    inherit [addr Tid.Map.t] Term.visitor
    method! enter_term _ t addrs = match Term.get_attr t address with
      | None -> begin
          match !last_addr with
          | Some addr -> Map.set addrs ~key:(Term.tid t) ~data:addr
          | None -> addrs
      end
      | Some addr -> begin
          last_addr := Some addr;
          Map.set addrs ~key:(Term.tid t) ~data:addr
        end
    end)#run prog Tid.Map.empty


let tid_to_string tid = Bap.Std.Tid.name tid
