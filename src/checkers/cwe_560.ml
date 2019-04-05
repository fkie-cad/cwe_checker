open Bap.Std
open Core_kernel

let name = "CWE560"
let version = "0.1"

let check_umask_call program proj tid_map sub umask_call =
  Log_utils.warn "CHECKING"

let check_subfunction program proj tid_map sym_umask sub =
  if Symbol_utils.sub_calls_symbol program sub "umask" then
    begin
      Log_utils.warn "[%s] {%s} (Use of umask() with chmod-style Argument) Function %s calls umask"
                                             name
                                             version
                                             (Sub.name sub);
      Symbol_utils.get_direct_callsites_of_sub sub
      |> Seq.iter ~f:(fun x -> if Symbol_utils.calls_callsite_symbol x sym_umask
                       then check_umask_call program proj tid_map sub x
                       else ())
    end
  else
    ()

let check_subfunctions program proj tid_map sym_umask =
  Seq.iter (Term.enum sub_t program) ~f:(fun sub -> check_subfunction program proj tid_map sym_umask sub)

let check_cwe program proj tid_map _ _ =
  let sym = Symbol_utils.get_symbol_of_string program "umask" in
  match sym with
  | None -> ()
  | Some sym_umask -> check_subfunctions program proj tid_map sym_umask
