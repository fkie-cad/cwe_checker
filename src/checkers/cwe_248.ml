open Core_kernel
open Bap.Std

let name = "CWE248"
let version = "0.1"

(* Print the findings to the log *)
let print_uncatched_exception block_tid ~tid_map =
   Log_utils.warn
     "[%s] {%s} (Possibly Uncaught Exception) (Exception thrown at %s)."
     name
     version
     (Address_translation.translate_tid_to_assembler_address_string block_tid tid_map)

(* Extract the name of a direct call, if the block contains a direct call. *)
let extract_direct_call_symbol block =
  match Symbol_utils.extract_direct_call_tid_from_block block with
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
      match Symbol_utils.extract_direct_call_tid_from_block block with
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

(* Search for uncatched exceptions for each entry point into the binary.
    TODO: Exceptions, that are catched when starting from one entry point, but not from another, are masked this
    way. We should check whether this produces a lot of false negatives. *)
let check_cwe program project tid_map symbol_pairs _ =
  let entry_points = Symbol_utils.get_program_entry_points program in
  let _ = Seq.fold entry_points ~init:[] ~f:(fun already_checked_functions sub -> find_uncaught_exceptions ~tid_map:tid_map sub already_checked_functions program) in
  ()
