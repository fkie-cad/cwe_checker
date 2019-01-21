open Bap.Std
open Core_kernel.Std

let name = "CWE248"
let version = "0.1"

(* Print the findings to the log *)
let print_uncatched_exception block_tid ~tid_map =
   Log_utils.warn
     "[%s] {%s} (Possibly Uncaught Exception) (Exception thrown at %s)."
     name
     version
     (Address_translation.translate_tid_to_assembler_address_string block_tid tid_map)


(* Returns the symbol name if the block contains a direct jump to a symbol *)
let extract_direct_call_tid block =
  let jmp_instructions = Term.enum jmp_t block in
  Seq.fold jmp_instructions ~init:None ~f:(fun already_found instr ->
    match already_found with
      | Some(symb) -> Some(symb)
      | None ->
        match Jmp.kind instr with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call dst -> match Call.target dst with
            | Direct tid ->
              (* Tid.name tid is the name of the symbol.*)
              Some(tid)
            | _ -> None)

(* Extract the Tid of a direct call, if the block contains a direct call. *)
let extract_direct_call_symbol block =
  match extract_direct_call_tid block with
    | Some(tid) -> Some(Tid.name tid)
    | None -> None

(* check whether block contains a direct call to a symbol with name symbol_name *)
let contains_symbol block symbol_name =
  match extract_direct_call_symbol block with
    | Some(symb) -> symb = symbol_name
    | None -> false

  (* Checks whether a subfunction contains a catch block. *)
  let contains_catch subfunction =
    let blocks = Term.enum blk_t subfunction in
    Seq.exists blocks (fun block -> contains_symbol block "@__cxa_begin_catch")

(* Find all calls to subfunctions that are reachable from this subfunction. The calls are returned
    as a list, except for calls to "@__cxa_throw", which are logged as possibly uncaught exceptions. *)
let find_calls_and_throws subfunction ~tid_map =
  let blocks = Term.enum blk_t subfunction in
  Seq.fold blocks ~init:[] ~f:(fun call_list block ->
    if contains_symbol block "@__cxa_throw" then
      let () = print_uncatched_exception  (Term.tid block) ~tid_map:tid_map in
      call_list
    else
      match extract_direct_call_tid block with
        | Some(tid) -> tid :: call_list
        | None -> call_list
  )

(* find exception throws with for which an exception handler was not necessarily allocated beforehand.
    The return value is a list of all already checked functions.*)
let rec find_uncaught_exceptions subfunction already_checked_functions program ~tid_map =
  if contains_catch subfunction then
    (* This function contains a catch so we assume every throw reachable from here is catched. *)
    already_checked_functions
  else
    let subfunction_calls = find_calls_and_throws subfunction ~tid_map:tid_map in
    List.fold subfunction_calls ~init:already_checked_functions ~f:(fun already_checked subfunc ->
      match List.exists ~f:(fun a -> a = subfunc) already_checked with
        | true -> already_checked
        | false ->  find_uncaught_exceptions ~tid_map:tid_map (Core_kernel.Option.value_exn (Term.find sub_t program subfunc)) (subfunc :: already_checked) program)


let check_cwe program tid_map =
  (* Get all subfunctions *)
  let subfunctions = Term.enum sub_t program in
  (* collect all entry points of the program *)
  let entry_points = Seq.filter subfunctions ~f:(fun subfn -> Term.has_attr subfn Sub.entry_point) in
  (* TODO: The _start entry point calls a libc-function which then calls the main function. Since right now only direct
      calls are tracked, our graph traversal never finds the main function. For now, we add it by hand to the entry points.*)
  let main_fn = Seq.filter subfunctions ~f:(fun subfn -> "@main" = Tid.name (Term.tid subfn)) in
  let entry_points_with_main = Seq.append main_fn entry_points in
  (* search for uncatched exceptions for each entry point, but accumulate the list of already checked functions. *)
  (* TODO: Exceptions, that are catched when starting from one entry point, but not from another, are masked this
      way. We should check whether this produces a lot of false negatives. *)
  let _ = Seq.fold entry_points_with_main ~init:[] ~f:(fun already_checked_functions sub -> find_uncaught_exceptions ~tid_map:tid_map sub already_checked_functions program) in
  ()
