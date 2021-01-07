open Core_kernel
open Bap.Std


let call_objdump (proj : Project.t) ~flag:(flag : string) ~err:(err : string) : string list =
  match Project.get proj filename with
  | None -> failwith "[cwe_checker] Project has no file name."
  | Some(fname) -> begin
      try
        let cmd = Format.sprintf ("objdump %s %s") flag fname in
        let in_chan = Caml_unix.open_process_in cmd in
        let lines = In_channel.input_lines in_chan in
        let () = In_channel.close in_chan in
        lines
      with
        Caml_unix.Unix_error (e,fm,argm) ->
          failwith (Format.sprintf "%s %s %s %s" err (Caml_unix.error_message e) fm argm)
    end
