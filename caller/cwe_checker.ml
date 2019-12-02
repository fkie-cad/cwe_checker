open Core_kernel

exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception InvalidModulesException of string
exception NoConfigException of string
exception InvalidFlagException of string
exception NoArgumentsException of string
exception NoBinaryPathException of string


let get_first ((a, _) : ('a * 'b)) : 'a = a


let get_second ((_, b) : ('a * 'b)) : 'b = b


let get_known_modules : string list =
  List.map ~f:(fun x -> x.name) Cwe_checker_core.Main.known_modules


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
  | None   -> print_endline "Using standard configuration..."
  | Some c ->
    match Stdlib.List.nth_opt (String.split c ~on:'=') 1 with
    | None | Some ""-> raise (NoConfigException "No config file provided. If -config flag set please provide a config file.")
    | Some f  -> if (Sys.file_exists f) then () else raise (InvalidPathException "Path to config file not valid")


let generate_output_file (path : string) ?(file="/out-" ^ string_of_float (Unix.time ())) ((): unit) : string =
  Printf.printf "Created: %s\n" (path ^ file);
  "-out=" ^ path ^ file


let build_path (path : string) : string =
  match String.is_suffix path ~suffix:"/" with
  | true  -> generate_output_file path ~file:("out-" ^ string_of_float (Unix.time ())) ()
  | false -> generate_output_file path ()


let extract_output_path (param : string) : string =
  try
    match Stdlib.List.nth (String.split param ~on:'=') 1 with
    | ""   -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")
    | out  -> out
  with
  | _ -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")


let output_check (input : string) : string =
  let path = extract_output_path input in
  try
    match Sys.is_directory path with
    | false -> "-out=" ^ path
    | true  -> build_path path
  with
  | _ -> raise (InvalidPathException "No valid path/file for output provided.")


let setup_flags (flags : string list) : string =
  String.concat ~sep:" " (List.map ~f:(fun pre -> "--cwe-checker" ^ pre) flags)


let check_modules (modules : string list) : unit =
  match get_difference modules get_known_modules with
  | [] -> ()
  | _  -> raise (InvalidModulesException ("Invalid CWE Modules. Known Modules: " ^ (String.concat (List.map ~f:(fun x -> x ^ " ") get_known_modules))))


let check_partial (input : string list) : unit =
  match find_prefix input "-partial" with
  | None   -> ()
  | Some p ->
    match Stdlib.List.nth_opt (String.split p ~on:'=') 1 with
    | None | Some "" ->  raise (NoModulesException "No modules provided. If -partial flag is set please provide the corresponding modules.")
    | Some modules   -> check_modules (String.split_on_chars modules ~on:[','])


let validate_user_input (input : string list) : unit =
  let valid_flags = List.map ~f:(fun x -> "-" ^ get_first x) Cwe_checker_core.Main.cmdline_flags in

  match get_difference input valid_flags with
  | []       -> ()
  | invalid  -> raise (InvalidFlagException ("Invalid flags: " ^ String.concat ~sep:", " invalid))


let help ((): unit) : unit =
  let flags = Cwe_checker_core.Main.cmdline_flags in
  let params = Cwe_checker_core.Main.cmdline_params in
  Printf.printf("Help:\n\nThe CWE checker is called using the following command structure:\n\n
  cwe_checker path/to/binary -[FLAG] -[PARAM] ...\n\nThe following flags and parameters are available:\n\nFLAGS:\n\n");
  List.iter ~f:(fun x -> Printf.printf "    -%s: %s\n" (get_first x) (get_second x)) flags;
  Printf.printf("\nPARAMETERS:\n\n");
  List.iter ~f:(fun x -> Printf.printf "    -%s: %s\n" (get_first x) (get_second x)) params


let check_for_help (flags: string list) : bool =
  if (Stdlib.List.mem "-h" flags) then (
    help (); true
  ) else if (Stdlib.List.mem "--help" flags) then (
    help(); true
  ) else false


let process_flags (flags : string list) : string list =
  match flags with
  | [] -> []
  | _  -> validate_user_input flags; flags


let process_params (params : string list) : string list =
  match params with
  | [] -> []
  | _  -> (
      match find_prefix params "-out" with
      | None -> params
      | Some o  -> replace_element params "-out" (output_check o)
    )


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


let process_input : string * string list =
  match get_user_input () with
  | [] -> raise (NoBinaryPathException ("No binary path was provided. If you need help, please call the cwe_checker with the --help or -h flag"))
  | input  -> (
      match check_for_help input with
      | true -> exit 0
      | false -> (
          let binary_path = check_for_binary_path input in
          let split_flags = List.partition_tf input ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out") || (String.is_prefix x ~prefix:"-partial")) in
          let flags = remove_element (snd split_flags) binary_path in
          let params = fst split_flags in
          check_partial params; check_config params;
          (binary_path,  process_params params @ process_flags flags)
        )
    )


let main () : int =
  match Array.length Sys.argv with
  | 1 -> raise (NoArgumentsException ("No arguments were provided. If you need help, please call the cwe_checker with the --help or -h flag"))
  | _ ->
    let args = process_input in
    match get_second args with
    | [] -> Sys.command ("bap " ^ get_first args ^ " --pass=cwe-checker ")
    | _  -> Sys.command ("bap " ^ get_first args ^ " --pass=cwe-checker " ^ setup_flags (get_second args))


let _ = main ()
