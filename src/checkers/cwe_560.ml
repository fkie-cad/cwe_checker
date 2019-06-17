open Core_kernel
open Bap.Std

let name = "CWE560"
let version = "0.1"

let upper_bound_of_correct_umask_arg_value = 100

let check_umask_call program proj tid_map blk =
  Log_utils.warn "HERE check_umask_call";
  Seq.iter (Term.enum def_t blk) ~f:(fun d -> match Exp.eval @@ Def.rhs d with
      | Imm w ->
        begin
          try
            let umask_arg = Word.to_int_exn w in
            Log_utils.warn "umask_arg: %d" umask_arg;
            if umask_arg  > upper_bound_of_correct_umask_arg_value then
              Log_utils.warn "[%s] {%s} (Use of umask() with chmod-style Argument) Function %s calls umask with argument %d"
                                             name
                                             version
                                             (Address_translation.translate_tid_to_assembler_address_string (Term.tid blk) tid_map)
                                             umask_arg
        with _ -> Log_utils.error "Caught exception in module [CWE560]."
      end
      | _ -> ())

let blk_calls_umask sym_umask sub blk =
  Term.enum jmp_t blk
  |> Seq.exists ~f:(fun callsite -> Symbol_utils.calls_callsite_symbol callsite sym_umask)

let check_subfunction program proj tid_map sym_umask sub =
  if Symbol_utils.sub_calls_symbol program sub "umask" then
    begin
      Term.enum blk_t sub
      |> Seq.filter ~f:(fun blk -> blk_calls_umask sym_umask sub blk)
      |> Seq.iter ~f:(fun blk -> check_umask_call program proj tid_map blk)
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
