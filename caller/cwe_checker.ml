open Core_kernel

exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception InvalidModulesException of string
exception NoConfigException of string

let known_modules = ["CWE190"; "CWE215"; "CWE243"; "CWE248"; "CWE332";
                     "CWE367"; "CWE426"; "CWE457"; "CWE467"; "CWE476";
                     "CWE560"; "CWE676"; "CWE782"]


let rec get_difference (set_a : 'a list) (set_b: 'a list) : 'a list =
  match set_a with
  | [] -> []
  | element_of_a::remain_a ->
    match (Stdlib.List.mem element_of_a set_b) with
    | true  -> get_difference remain_a set_b
    | false -> List.append (get_difference remain_a set_b) [element_of_a]


let get_user_input ?(position=1) (() : unit) : string list =
  Array.to_list (Array.sub Sys.argv ~pos:position ~len:(Array.length Sys.argv - position))


let rec find_prefix (input : string list) (prefix : string) : string option =
  match input with
  | []         -> None
  | head::tail ->
    match (String.is_prefix head ~prefix:prefix) with
    | true  -> Some head
    | false -> find_prefix tail prefix


let rec replace_element (set : string list) (element : string) (replacement : string) : string list =
  match set with
  | []         -> []
  | head::tail ->
    match String.is_prefix ~prefix:element head with
    | true  -> replacement::tail
    | false -> head::replace_element tail element replacement


let config_check (input : string list) : bool =
  match find_prefix input "-config" with
  | None   -> print_endline "Using standard configuration..."; true
  | Some c ->
    match Stdlib.List.nth_opt (String.split c ~on:'=') 1 with
    | None | Some ""-> raise (NoConfigException "No config file provided. If -config flag set please provide a config file.")
    | Some f  -> if (Sys.file_exists f) then true else raise (InvalidPathException "Path to config file not valid")


let generate_output_file (path : string) ?(file="/out-" ^ string_of_float (Unix.time ())) ((): unit) : string =
  Printf.printf "Created: %s\n" (path ^ file);
  "-out=" ^ path ^ file


let build_path (path : string) : string =
  match String.is_suffix path ~suffix:"/" with
  | true  -> generate_output_file path ~file:("out-" ^ string_of_float (Unix.time ())) ()
  | false -> generate_output_file path ()


let out_path (path : string) : string =
  try
    match Sys.is_directory path with
    | false -> generate_output_file path ~file:"" ()
    | true  -> build_path path
  with
  | _ -> raise (InvalidPathException "No valid path/file for output provided.")


let out_check (input : string) : string =
  try
    let output_file = Stdlib.List.nth (String.split input ~on:'=') 1 in
    out_path output_file
  with
  | _ -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")


let setup_flags (flags : string list) : string =
  String.concat ~sep:" " (List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags)


let partial_check (input : string list) : bool =
  match find_prefix input "-partial" with
  | None   -> true
  | Some p ->
    match Stdlib.List.nth_opt (String.split p ~on:'=') 1 with
    | None | Some "" ->  raise (NoModulesException "No modules provided. If -partial flag is set please provide the corresponding modules.")
    | Some modules  ->
      let modules = String.split_on_chars modules ~on:[','] in
      if get_difference modules known_modules <> [] then (
        let print_modules = String.concat (List.map ~f:(fun x -> x ^ " ") known_modules) in
        raise (InvalidModulesException ("Invalid CWE Modules. Known Modules: " ^ print_modules))
      )
      else true


let get_from_json (path : string): string list =
 let json = Yojson.Basic.from_file path in
 let open Yojson.Basic.Util in
 json |> member "flags" |> to_list |> filter_string


let user_input_valid (input : string list) : bool =
  (* let valid_flags = get_from_json "" in *)
  let valid_flags = ["-config"; "-module-versions"; "-json"; "-no-logging"; "-out"; "-partial"] in
  let invalid_flags = get_difference input valid_flags in

  match invalid_flags with
  | [] -> true
  | _  -> List.iter ~f:(fun x -> Printf.printf "Invalid flag: %s\n" x) invalid_flags; false


let process_flags : string list option =
  match get_user_input ~position:2 () with
  | [] -> Some []
  | flags  ->
    let split_flags = List.partition_tf flags
        ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in

    match fst split_flags with
    | [] -> if user_input_valid (snd split_flags) then Some (snd split_flags) else None
    | flags -> (
      match find_prefix (flags) "-out" with
      | None -> if partial_check flags && config_check flags then Some flags else None
      | Some o -> (
        let new_flags = replace_element (flags) "-out" (out_check o) in
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
