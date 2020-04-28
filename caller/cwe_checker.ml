open Core_kernel
open Cwe_checker_core.Main

exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception NoConfigException of string
exception NoBinaryPathException of string
exception NoApiFileException of string


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


let raise_no_content_exception (param : string) : unit =
  match param with
  | "-config" -> raise (NoConfigException "No config file provided. If -config flag set please provide a config file.")
  | "-out" -> raise (NoOutputFileException "No output file provided. If -out flag is set please provide an out file.")
  | "-partial" -> raise (NoModulesException "No modules provided. If -partial flag is set, please provide the corresponding modules.")
  | "-api" -> raise (NoApiFileException "No header file provided. If -api flag is set, please provide a valid header file.")
  | _ -> failwith "Invalid param."


let check_content (input : string) (param : string) : unit =
  match Stdlib.List.nth_opt (String.split input ~on:'=') 1 with
  | None | Some "" -> raise_no_content_exception param
  | Some content -> begin
      match param with
      | "-partial" -> check_valid_module_list (String.split_on_chars content ~on:[','])
      | "-config" | "-api" -> if (Sys.file_exists content) then () else raise (InvalidPathException "Path to config file not valid")
      | _ -> ()
    end


let check_params (params : string list) (input : string list) : unit =
  List.iter params ~f:(fun param ->
    match find_prefix input param with
    | None -> begin
        match (String.equal param "-config") with
        | true -> Cwe_checker_core.Log_utils.info "Using standard configuration..."
        | false -> ()
      end
    | Some p -> check_content p param
  )


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


let process_input (() : unit) : string * string list =
  match get_user_input () with
  | [] -> raise (NoBinaryPathException ("No binary path was provided. If you need help, please call the cwe_checker with the --help or -h flag"))
  | input  -> (
      if check_for_help input then exit 0;
      if check_for_version input then exit 0;
      if check_for_module_versions input then exit 0;
      check_for_no_logging input;
      let binary_path = check_for_binary_path input in
      let split_flags = List.partition_tf input ~f:(fun x -> (String.is_prefix x ~prefix:"-config") || (String.is_prefix x ~prefix:"-out")
                                                             || (String.is_prefix x ~prefix:"-partial") || (String.is_prefix x ~prefix:"-api")) in
      let flags = remove_element (snd split_flags) binary_path in
      let input_params = fst split_flags in
      let params = List.map cmdline_params ~f:(fun param -> match param with | (p, _) -> "-" ^ p) in
      check_params params input_params;
      (binary_path, input_params @ process_flags flags)
    )


let setup_command (bin_path : string) (args : string list) : string =
  let bare_command = "bap " ^ bin_path ^ " --pass=cwe-checker " in
  let command_args = String.concat ~sep:" " (List.map args ~f:(fun arg ->
    match (String.is_prefix arg ~prefix:"-api") with
    | true -> "--api-path=" ^ (Stdlib.List.nth (String.split arg ~on:'=') 1)
    | false -> "--cwe-checker" ^ arg)) in
  bare_command ^ command_args



let main () : int =
  match Array.length Sys.argv with
  | 1 -> print_help_message (); 0
  | _ ->
      let (bin_path, args) = process_input () in
      match args with
      | [] -> Sys.command ("bap " ^ bin_path ^ " --pass=cwe-checker ")
      | _  -> Sys.command (setup_command bin_path args)


let _ = exit (main ())
