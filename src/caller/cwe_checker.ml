open Core_kernel

exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception InvalidModulesException of string
exception NoConfigException of string

let known_modules = ["CWE190"; "CWE215"; "CWE243"; "CWE248"; "CWE332";
                     "CWE367"; "CWE426"; "CWE457"; "CWE467"; "CWE476";
                     "CWE560"; "CWE676"; "CWE782"]


let config_check (input : string list) : bool =
  match Helper_functions.find_prefix input "-config" with
  | None   -> print_endline "Using standard configuration..."; true
  | Some c ->
    match Stdlib.List.nth_opt (String.split c ~on:'=') 1 with
    | None | Some ""-> raise (NoConfigException "No config file provided. If -config flag set please provide a config file.")
    | Some f  -> if (Sys.file_exists f) then true else raise (InvalidPathException "Path to config file not valid")


let generate_output_file (path : string) ?(file="/out-" ^ string_of_float (Unix.time ())) ((): unit) : string =
  Printf.printf "Created: %s\n" (path ^ file);
  "-out=" ^ path ^ file


let check_suffix (path : string) : string =
match (String.is_suffix path ~suffix:".json" || String.is_suffix path ~suffix:".txt") with
| false ->
  Printf.printf "File: %s  is not a valid out file.\nData is written to new file.\n" path;
  generate_output_file (fst (String.rsplit2_exn path ~on:'/')) ()
| true -> generate_output_file path ~file:"" ()


let build_path (path : string) : string =
  match String.is_suffix path ~suffix:"/" with
  | true  -> generate_output_file path ~file:("out-" ^ string_of_float (Unix.time ())) ()
  | false -> generate_output_file path ()


let out_path (path : string) : string =
  try
    match Sys.is_directory path with
    | false -> check_suffix path
    | true  -> build_path path
  with
  | _ -> raise (InvalidPathException "No valid path/file for output provided.")


let out_check (input : string) : string =
  try
    out_path (Stdlib.List.nth (String.split input ~on:'=') 1)
  with
  | _ -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")


let setup_flags (flags : string list) : string =
  String.concat ~sep:" " (List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags)


let partial_check (input : string list) : bool =
  match Helper_functions.find_prefix input "-partial" with
  | None   -> true
  | Some p ->
    match Stdlib.List.nth_opt (String.split p ~on:'=') 1 with
    | None | Some "" ->  raise (NoModulesException "No modules provided. If -partial flag is set please provide the corresponding modules.")
    | Some modules  ->
      let modules = String.split_on_chars modules ~on:[','] in
      if Helper_functions.get_difference modules known_modules <> [] then (
        let print_modules = String.concat (List.map ~f:(fun x -> x ^ " ") known_modules) in
        raise (InvalidModulesException ("Invalid CWE Modules. Known Modules: " ^ print_modules))
      )
      else true


(* Get valid flags from a json file *)
let get_from_json (path : string): string list =
 let json = Yojson.Basic.from_file path in
 let open Yojson.Basic.Util in
 json |> member "flags" |> to_list |> filter_string


(* Check if binary path is provided and if all flags are valid *)
let user_input_valid (input : string list) : bool =
  let valid_flags = get_from_json "/home/melvin/Dokumente/Developer/OCaml_Projects/quickstart/bin/cwe_cmd.json" in
  let invalid_flags = Helper_functions.get_difference input valid_flags in

  match invalid_flags with
  | [] -> true
  | _  -> List.iter ~f:(fun x -> Printf.printf "Invalid flag: %s\n" x) invalid_flags; false


let process_flags : string list option =
  match Helper_functions.get_user_input ~position:2 () with
  | [] -> Some []
  | flags  ->
    let split_flags = List.partition_tf flags
        ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in

    match fst split_flags with
    | [] -> if user_input_valid (snd split_flags) then Some (snd split_flags) else None
    | flags -> (
      match Helper_functions.find_prefix (flags) "-out" with
      | None -> if partial_check flags && config_check flags then Some flags else None
      | Some o -> (
        let new_flags = Helper_functions.replace_element (flags) "-out" (out_check o) in
        if partial_check flags && config_check flags then Some ((snd (split_flags)) @ new_flags) else None
      )
    )


let main () : int =
  match Array.length Sys.argv with
  | 1 -> Sys.command ("bap " ^ Sys.argv.(1) ^ " --pass=cwe-checker ")
  | _ ->
    match process_flags with
    | None -> 1
    | Some [] -> Sys.command ("bap " ^ Sys.argv.(1) ^ " --pass=cwe-checker ")
    | Some flags -> Sys.command ("bap " ^ Sys.argv.(1) ^ " --pass=cwe-checker " ^ setup_flags flags)


let _ = main ()
