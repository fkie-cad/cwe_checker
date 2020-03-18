open Core_kernel
open Bap.Std
open Log_utils

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

(* TODO: check if program contains strings like "DEBUG"*)
let check_cwe _ project _ _ _ =
  match Project.get project filename with
  | Some fname -> begin
      let cmd = Format.sprintf "objdump --dwarf=decodedline %s | grep CU" fname in
      try
        let in_chan = Unix.open_process_in cmd in
        In_channel.input_lines in_chan |> List.iter ~f:(fun l ->
                                              let description = sprintf "(Information Exposure Through Debug Information) %s" l in
                                              let cwe_warning = cwe_warning_factory name version description ~symbols:[l] in
                                              collect_cwe_warning cwe_warning)


      with
        Unix.Unix_error (e,fm,argm) ->
        Log_utils.error (sprintf "[%s] {%s} %s %s %s" name version (Unix.error_message e) fm argm)
    end
  | _ -> failwith "[CWE215] symbol_names not as expected"
