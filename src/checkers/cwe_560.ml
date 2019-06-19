open Core_kernel
open Bap.Std

let name = "CWE560"
let version = "0.1"

let upper_bound_of_correct_umask_arg_value = 100
let upper_bound_of_correct_chmod_arg_value = 1000

 let collect_int_values = Exp.fold ~init:[] (object
          inherit [word list] Exp.visitor
          method! enter_int x addrs = x :: addrs
        end)

let is_chmod_style_arg umask_arg =
  umask_arg  > upper_bound_of_correct_umask_arg_value && umask_arg < upper_bound_of_correct_chmod_arg_value

let check_umask_arg tid_map blk w =
  try
    let umask_arg = Word.to_int_exn w in
    if is_chmod_style_arg umask_arg then
      Log_utils.warn "[%s] {%s} (Use of umask() with chmod-style Argument) Function %s calls umask with argument %d"
        name
        version
        (Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map)
        umask_arg
  with _ -> Log_utils.error "Caught exception in module [CWE560]."

let check_umask_callsite tid_map blk =
  Seq.iter (Term.enum def_t blk) ~f:(fun d ->
   let rhs = Def.rhs d in
   let int_values = collect_int_values rhs in
   List.iter int_values ~f:(fun x -> check_umask_arg tid_map blk x)
  )

let blk_calls_umask sym_umask blk =
  Term.enum jmp_t blk
  |> Seq.exists ~f:(fun callsite -> Symbol_utils.calls_callsite_symbol callsite sym_umask)

let check_subfunction program tid_map sym_umask sub =
  if Symbol_utils.sub_calls_symbol program sub "umask" then
    Term.enum blk_t sub
    |> Seq.filter ~f:(fun blk -> blk_calls_umask sym_umask blk)
    |> Seq.iter ~f:(fun blk -> check_umask_callsite tid_map blk)
  else
    ()

let check_subfunctions program tid_map sym_umask =
  Seq.iter (Term.enum sub_t program) ~f:(fun sub -> check_subfunction program tid_map sym_umask sub)

let check_cwe program _ tid_map _ _ =
    let sym = Symbol_utils.get_symbol_of_string program "umask" in
    match sym with
    | None -> ()
    | Some sym_umask -> check_subfunctions program tid_map sym_umask


(* Functions made available for unit tests *)
module Private = struct
  let is_chmod_style_arg = is_chmod_style_arg
end
