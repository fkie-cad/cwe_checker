open Core_kernel
open Symbol_utils
open Log_utils

let name = "CWE332"
let version = "0.1"

let check_cwe program _proj _tid_map _symbol_pairs _ =
  match Option.both (find_symbol program "srand") (find_symbol program "rand") with
  | None -> begin
      match (find_symbol program "rand") with
      | None -> ()
      | Some _ -> begin
          let description = "(Insufficient Entropy in PRNG) program uses rand without calling srand before" in
          let cwe_warning = cwe_warning_factory name version description in
          collect_cwe_warning cwe_warning
        end
    end
  | Some (_srand_tid, _rand_tid) -> ()
