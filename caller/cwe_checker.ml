open Core_kernel
open Cwe_checker_core.Main

exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception NoConfigException of string
exception NoBinaryPathException of string


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


let rec remove_element (flags : string list) (element: string): string list =
  match flags with
  | [] -> []
  | head::tail ->
      match String.is_prefix ~prefix:element head with
      | true -> tail
      | false -> head::remove_element tail element


let check_config (input : string list) : unit =
  match find_prefix input "-config" with
  | None   -> Cwe_checker_core.Log_utils.info "Using standard configuration..."
  | Some c ->
    match Stdlib.List.nth_opt (String.split c ~on:'=') 1 with
    | None | Some ""-> raise (NoConfigException "No config file provided. If -config flag set please provide a config file.")
    | Some f  -> if (Sys.file_exists f) then () else raise (InvalidPathException "Path to config file not valid")


let check_output_path (input : string list) : unit =
  match find_prefix input "-out" with
  | Some param -> begin
      try
        match Stdlib.List.nth (String.split param ~on:'=') 1 with
        | ""   -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")
        | _  -> ()
      with
      | _ -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")
    end
  | None -> ()


let setup_flags (flags : string list) : string =
  String.concat ~sep:" " (List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags)


let check_partial (input : string list) : unit =
  match find_prefix input "-partial" with
  | None   -> ()
  | Some p ->
    match Stdlib.List.nth_opt (String.split p ~on:'=') 1 with
    | None | Some "" ->  raise (NoModulesException "No modules provided. If -partial flag is set please provide the corresponding modules.")
    | Some modules   ->  check_valid_module_list (String.split_on_chars modules ~on:[','])


let validate_user_input (input : string list) : unit =
  let valid_flags = List.map ~f:(fun x -> "-" ^ fst x) Cwe_checker_core.Main.cmdline_flags in

  match get_difference input valid_flags with
  | []       -> ()
  | invalid  -> failwith ("Invalid flags: " ^ String.concat ~sep:", " invalid)


let check_for_help (flags: string list) : bool =
  if (Stdlib.List.mem "-h" flags)|| (Stdlib.List.mem "-help" flags) || (Stdlib.List.mem "--help" flags) then (
    print_help_message (); true
  ) else false

let check_for_version (flags:string list) : bool =
  if (Stdlib.List.mem "-v" flags) || (Stdlib.List.mem "-version" flags) || (Stdlib.List.mem "--version" flags) then (
    print_version (); true
  ) else false

let check_for_module_versions (flags: string list) : bool =
  if Stdlib.List.mem "-module-versions" flags then
    let () = Cwe_checker_core.Main.print_module_versions () in
    true
  else
    false


let check_for_no_logging (flags: string list) : unit =
  if Stdlib.List.mem "-no-logging" flags then
    Cwe_checker_core.Log_utils.turn_off_logging ()


let process_flags (flags : string list) : string list =
  match flags with
  | [] -> []
  | _  -> validate_user_input flags; flags


let rec check_for_binary_path (args : string list) : string =
  match args with
  | [] -> raise (NoBinaryPathException ("No binary path was provided. If you need help, please call the cwe_checker with the --help or -h flag"))
  | head::tail ->(
      try
        match Sys.is_directory head with
        | false -> head
        | true  -> raise (NoBinaryPathException ("No binary path was provided. If you need help, please call the cwe_checker with the --help or -h flag"))
      with
      | _ -> check_for_binary_path tail
   )


let process_input () : string * string list =
  match get_user_input () with
  | [] -> raise (NoBinaryPathException ("No binary path was provided. If you need help, please call the cwe_checker with the --help or -h flag"))
  | input  -> (
      if check_for_help input then exit 0;
      if check_for_version input then exit 0;
      if check_for_module_versions input then exit 0;
      check_for_no_logging input;
      let binary_path = check_for_binary_path input in
      let split_flags = List.partition_tf input ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in
      let flags = remove_element (snd split_flags) binary_path in
      let params = fst split_flags in
      check_partial params; check_config params; check_output_path params;
      (binary_path, params @ process_flags flags)
    )


let main () : int =
  match Array.length Sys.argv with
  | 1 -> print_help_message (); 0
  | _ ->
      let args = process_input () in
      match snd args with
      | [] -> Sys.command ("bap " ^ fst args ^ " --pass=cwe-checker ")
      | _  -> Sys.command ("bap " ^ fst args ^ " --pass=cwe-checker " ^ setup_flags (snd args))


let _ = exit (main ())
