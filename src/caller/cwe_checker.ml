open Core_kernel


(* Get all command line arguments starting at index 2 and put them into a list*)
let get_user_flags : string list =
  Array.to_list (Array.sub Sys.argv ~pos:2 ~len:(Array.length Sys.argv - 2))


(*
   retrieves the config flag including the config file
   if no config flag is given an empty string is returned
*)
let rec get_config (input : string list): string option =
  match input with
  | [] -> None
  | head::tail ->
    match (String.substr_index head ~pattern:"-config=") with
    | Some 0 -> Some head
    | _ -> get_config tail


let config_check_failed (input : string list) : bool =
  let config = get_config input in

  match config with
  | None -> true
  | Some c ->
    let file = Stdlib.List.nth (String.split c ~on:'=') 1 in

    if (String.substr_index file ~pattern:".json") = None then (
      Printf.printf "File format of %s has to be json.\n" file;
      true
    ) else if not (Sys.file_exists file) then (
      Printf.printf "%s is not a valid path.\n" file;
      true
    ) else false



(* #############################################################################
   Here check for -out flag
   #############################################################################
*)


(* #############################################################################
   Here check for -partial flag
   #############################################################################
*)


(*
   take all elements of the user input starting from index 2,
   prefix the flags with --cwe-checker- and return a
   concatenated string
*)
let setup_flags (flags : string list) : string =
  let flags = List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags in
  String.concat ~sep:" " flags


(*
   Compare user given flags and compare them with valid flags.
   Return a list of invalid flags.
*)
let rec compare_element_wise (user_input : string list) (valid_flags: string list) : string list =
  match user_input with
  | [] -> []
  | head::tail ->
    match (Stdlib.List.mem head valid_flags) with
    | true -> compare_element_wise tail valid_flags
    | false -> List.append (compare_element_wise tail valid_flags) [head]


(* Get valid flags from a json file *)
let get_from_json : string list =
 let json = Yojson.Basic.from_file "/home/melvin/Dokumente/Developer/OCaml_Projects/quickstart/cwe_cmd.json" in
 let open Yojson.Basic.Util in
 json |> member "flags" |> to_list |> filter_string


(* Check if binary path is provided and if all flags are valid *)
let user_input_valid (input : string list) : bool =
  let valid_flags = get_from_json in
  let input_len = List.length input in

  match input_len with
  | 1 -> print_endline "No binary path provided"; false
  | 2 -> true
  | _ ->
    let invalid_flags = compare_element_wise input valid_flags in

    match invalid_flags with
    | [] -> true
    | _  ->
      List.iter ~f:(fun x -> Printf.printf "Invalid flag: %s\n" x) invalid_flags;
      false


let main () : int =
  let flags = get_user_flags in

  let split_flags = List.partition_tf flags
      ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in

  if config_check_failed (fst split_flags) then print_endline "Using standard configuration...";

  match (user_input_valid (snd split_flags)) with
  | false -> 1
  | true ->
    let path_to_binary = Sys.argv.(1) in
    Sys.command ("bap " ^ path_to_binary ^ " --pass=cwe-checker " ^ setup_flags flags)


let _ = main ()
