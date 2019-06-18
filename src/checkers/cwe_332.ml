open Core_kernel

open Symbol_utils

let name = "CWE332"
let version = "0.1"

let check_cwe program _proj _tid_map _symbol_pairs _ =
  match Option.both (find_symbol program "srand") (find_symbol program "rand") with
  | None -> begin
      match (find_symbol program "rand") with
      | None -> ()
      | Some _ -> Log_utils.warn "[%s] {%s} (Insufficient Entropy in PRNG) program uses rand without calling srand before" name version
    end
  | Some (_srand_tid, _rand_tid) -> ()
