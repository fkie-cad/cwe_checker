open Bap.Std
open Core_kernel.Std

let name = "CWE248"
let version = "0.1"

(* filters all jump instructions for exception throw calls that have no return address (according to bap).
   ToDo: This produces too many false positives right now. *)
let find_exceptions block =
  let jmp_instructions = Term.enum jmp_t block in
    Seq.filter_map jmp_instructions ~f:(fun instr ->
      match Jmp.kind instr with
        | Goto _ | Ret _ | Int (_,_) -> None
        | Call dst -> match Call.target dst with
          | Direct tid ->
            (* Tid.name tid is the name of the extern symbol. We are interested in the symbols @__cxa_throw and
              and @__cxa_allocate_exception. Term.name instr contains the address of the instruction.*)
            if Tid.name tid = "@__cxa_throw" && dst = Call.with_noreturn dst then
              Some (Term.tid block)
            else
              None
          | _ -> None)

let print_calls calls ~tid_map =
   Seq.iter calls ~f:(fun call -> match call with
      | block_tid -> Log_utils.warn
                       "[%s] {%s} (Possibly Uncaught Exception) (Exception thrown at %s)."
                       name
                       version
                       (Address_translation.translate_tid_to_assembler_address_string block_tid tid_map))


let check_cwe program tid_map =
  (* Get all subfunctions *)
  let subfunctions = Term.enum sub_t program in
  (* Get all blocks of code *)
  let blocks = Seq.concat_map subfunctions ~f:(fun subfunction -> Term.enum blk_t subfunction) in
  (* Filter for possibly uncaught exception throws *)
  let exception_throws = Seq.concat_map blocks ~f:(fun block -> find_exceptions block) in
  (* print *)
  print_calls exception_throws ~tid_map:tid_map


(* Der Segfault schaint das Ausführen von find_exception_throws zu sein. Er kommt nicht in die Funktion rein,
  aber direkt davor ist das Programm noch am Leben *)
