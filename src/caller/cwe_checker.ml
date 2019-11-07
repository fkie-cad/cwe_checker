open Core_kernel
open Lib

let known_modules = ["CWE190"; "CWE215"; "CWE243"; "CWE248"; "CWE332";
                     "CWE367"; "CWE426"; "CWE457"; "CWE467"; "CWE476";
                     "CWE560"; "CWE676"; "CWE782"]


let config_check_message (input : string list) : string option =
  let config = Helper_functions.find_prefix input "-config=" in

  match config with
  | None   -> Some "Using standard configuration..."
  | Some c ->
    let file = Stdlib.List.nth (String.split c ~on:'=') 1 in

    match file with
    | "" -> Some "No config file provided. If -config flag set please provide a config file."
    | _  -> if (Sys.file_exists file) then None else Some (file ^ ". Path is not valid.")


let config_check (input : string list) : bool =
  match config_check_message input with
  | None -> true
  | Some message -> (print_endline message); false


let out_path (path : string) : string option =
  (* let components = String.split_on_chars path ~on:['/'] in *)
  try
    match Sys.is_directory path with
    | false -> Some path
    | true  ->
      match String.is_suffix path ~suffix:"/" with
      | true  ->
        if path = "/" then Some (Sys.getcwd () ^ path ^ ("out-" ^ string_of_float (Unix.time ())))
        else Some (path ^ ("out-" ^ string_of_float (Unix.time ())))
      | false -> Some (path ^ ("/out-" ^ string_of_float (Unix.time ())))
  with
  | _ ->
    let components = String.split_on_chars path ~on:['/'] in
    let file = List.last components in
    let new_path = Helper_functions.remove_nth components ((List.length components) - 1) in
    match new_path with
    | [] -> Some (Sys.getcwd () ^ "/" ^ Helper_functions.get_default_string file)
    | [""] -> Some (Sys.getcwd () ^ "/" ^ Helper_functions.get_default_string file)
    | _  ->
      try
        let new_path = (String.concat ~sep:"/" new_path) in
        ignore (Sys.is_directory new_path);
        Some (new_path ^ "/" ^ Helper_functions.get_default_string file)
      with
      | _ -> Printf.printf "Path: %s given for -out flag is invalid.\n" path; Some "failed"



let out_check (input : string list) : string option =
  let out = Helper_functions.find_prefix input "-out=" in

  match out with
  | None   -> None
  | Some o ->
    let path = Stdlib.List.nth (String.split o ~on:'=') 1 in
    match path with
    | "" -> print_endline "No out file provided. If -out flag is set please provide an out file."; Some ""
    | p  -> out_path p


  (*
     take all elements of the user input starting from index 2,
     prefix the flags with --cwe-checker- and return a
     concatenated string
  *)
let setup_flags (flags : string list) : string =
  let flags = List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags in
  String.concat ~sep:" " flags


let partial_check (input : string list) : bool =
  let partial = Helper_functions.find_prefix input "-partial=" in

  match partial with
  | None   -> true
  | Some p ->
    let modules = Stdlib.List.nth (String.split p ~on:'=') 1 in
    match modules with
    | "" ->
      print_endline "No modules provided. If -partial flag is set please provide the corresponding modules.\n This is a list of all supported modules:";
      List.iter ~f:(fun x -> Printf.printf "%s" x) known_modules;
      false
    | _  ->
      let modules = String.split_on_chars modules ~on:[','] in
      let invalid_modules = Helper_functions.get_difference modules input in
      match invalid_modules with
      | []  -> true
      | inv -> print_endline "Invalid CWE Modules:\n"; List.iter ~f:(fun x -> Printf.printf "%s" x) inv; false


(* Get valid flags from a json file *)
let get_from_json (path : string): string list =
 let json = Yojson.Basic.from_file path in
 let open Yojson.Basic.Util in
 json |> member "flags" |> to_list |> filter_string


(* Check if binary path is provided and if all flags are valid *)
let user_input_valid (input : string list) : bool =
  let valid_flags = get_from_json "/home/melvin/Dokumente/Developer/OCaml_Projects/quickstart/cwe_cmd.json" in
  let invalid_flags = Helper_functions.get_difference input valid_flags in

  match invalid_flags with
  | [] -> true
  | _  ->
    List.iter ~f:(fun x -> Printf.printf "Invalid flag: %s\n" x) invalid_flags;
    false


let process_flags : string list option =
  match Helper_functions.get_user_input ~position:2 () with
  | [] -> Some []
  | flags  ->
    let split_flags = List.partition_tf flags
        ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in
    let out = Helper_functions.find_prefix (fst split_flags) "-out" in
    let file_flags = Helper_functions.remove_element (fst split_flags) "-out" in
    



let main () : int =
  match process_flags with
  | None -> 1
  | Some [] -> Sys.command ("bap " ^ Sys.argv.(1) ^ " --pass=cwe-checker ")
  | Some flags -> Sys.command ("bap " ^ Sys.argv.(1) ^ " --pass=cwe-checker " ^ setup_flags flags)


let _ = main ()
