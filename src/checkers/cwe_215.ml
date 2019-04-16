open Core_kernel
open Bap.Std
open Unix

(* TODO: IVG via gitter:
I see, so you need the CU information, and yes BAP doesn't provide this.
The right way to do this thing (a little bit complicated, but it
will preserve the abstractions), would be the following:

 - Define the abstract interface for the CU providers (you can use Source module
    or just define it manually with the interface you like)
 - Write plugins that will provide implementations
   (i.e., using readelf, objdump, IDA, LLVM, or whatever). The implementation shall
subscribe to Project.Info.file information stream and generate CU information every time a new file is open.

Of course, for the prototype your approach will work,
but in general case it is better to use the approach described above. *)

let name = "CWE215"
let version = "0.1"

let read_lines in_chan =
  let lines = ref [] in
  try
    while true; do
      lines := input_line in_chan :: !lines
    done; !lines
  with End_of_file ->
    In_channel.close in_chan;
    List.rev !lines

(* TODO: check if program contains strings like "DEBUG"*)
let check_cwe _ project _ _ _ =
  match Project.get project filename with
  | Some fname -> begin
      let cmd = Format.sprintf "readelf --debug-dump=decodedline %s | grep CU" fname in
      try
        let in_chan = Unix.open_process_in cmd in
        read_lines in_chan |> List.iter ~f:(fun l -> Log_utils.warn "[%s] {%s} (Information Exposure Through Debug Information) %s" name version l)
      with
        Unix.Unix_error (e,fm,argm) ->
        Log_utils.error "[%s] {%s} %s %s %s" name version (Unix.error_message e) fm argm
    end
  | _ -> failwith "[CWE215] symbol_names not as expected"
