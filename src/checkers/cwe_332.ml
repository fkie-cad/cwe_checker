open Bap.Std
open Core_kernel.Std

open Graph_utils
open Symbol_utils

let name = "CWE332"
let version = "0.1"

let check_cwe program proj tid_map symbol_pairs _ =
  match Option.both (find_symbol program "srand") (find_symbol program "rand") with
  | None -> begin
      match (find_symbol program "rand") with
      | None -> ()
      | Some _ -> Log_utils.warn "[%s] {%s} (Insufficient Entropy in PRNG) program uses rand without calling srand before" name version
    end
  | Some (srand_tid, rand_tid) -> ()
