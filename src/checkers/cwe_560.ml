open Bap.Std
open Core_kernel

let name = "CWE560"
let version = "0.1"

let check_cwe program proj tid_map symbol_pairs _ =
  match find_symbol program "umask" with
  | None -> () 
  | Some umask_tid -> (* TODO *) ()
