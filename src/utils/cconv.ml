
open Bap.Std
open Core_kernel

let dyn_syms = ref None

let callee_saved_registers = ref None

let bin_format = ref ""

let json (() : unit) : Yojson.Basic.t =
  let path = match Sys.getenv_opt "OPAM_SWITCH_PREFIX" with
  | Some(prefix) -> prefix ^ "/etc/cwe_checker/registers.json"
  | None -> "" in
  Yojson.Basic.from_file path

let supported_architectures = ref []


let get_supported_architectures (() : unit) : string list =
  match !supported_architectures with
  | [] -> begin
      supported_architectures := List.append !supported_architectures (List.map (Json_utils.get_arch_list_from_json (json ()) "elf") ~f:(fun kv -> match kv with (k, _) -> k));
      !supported_architectures
  end
  | _  -> !supported_architectures


let call_objdump (proj : Project.t) (flag : string) (err : string) : string list =
  match Project.get proj filename with
  | None -> failwith "[cwe_checker] Project has no file name."
  | Some(fname) -> begin
      try
        let cmd = Format.sprintf ("objdump %s %s") flag fname in
        let in_chan = Unix.open_process_in cmd in
        let lines = In_channel.input_lines in_chan in
        let () = In_channel.close in_chan in
        lines
      with
        Unix.Unix_error (e,fm,argm) ->
          failwith (Format.sprintf "%s %s %s %s" err (Unix.error_message e) fm argm)
    end


let infer_bin_format_from_symbols (project : Project.t) : string =
  match Option.is_some (Symtab.find_by_name (Project.symbols project) "__GetPEImageBase") with
  | true -> "pe"
  | false -> "elf"


let extract_bin_format (project : Project.t) : string =
  match !bin_format with
  | "" -> begin
    let header = call_objdump project "-f" "[cwe_checker] Parsing of file header failed:" in
    let arch = Project.arch project in
    match header with
    | _::line::_ -> begin
        let chop_idx = match arch with
          | `x86_64 -> 2
          | _ -> 1 in
        match List.hd_exn (List.drop (List.rev (String.split_on_chars line ~on:[' '; '-'])) chop_idx) with
        | "elf32" | "elf64" -> bin_format := "elf"; !bin_format
        | "pei" -> bin_format := "pe"; !bin_format
        | _ -> infer_bin_format_from_symbols project
    end
    | _ -> infer_bin_format_from_symbols project
    end
  | _ -> !bin_format


let get_register_list (project : Project.t) (context : string) : string list =
  let arch = Arch.to_string (Project.arch project) in
  match Stdlib.List.mem arch (get_supported_architectures ()) with
  | true -> begin
      let json_bin = Json_utils.get_bin_format_from_json (json ()) (extract_bin_format project) in
      match arch with
      | "x86" -> begin
          let conv = match Project.get project Bap_abi.name with
            | Some(c) -> c
            | _ -> Log_utils.info "[cwe_checker] Could not infer calling convention. Assuming cdelc as standard"; "cdecl" in
          let json_arch = Json_utils.get_arch_from_json json_bin ~conv:conv arch in
          Json_utils.get_registers_from_json json_arch context
        end
      | _ -> begin
          let json_arch = Json_utils.get_arch_from_json json_bin arch in
          Json_utils.get_registers_from_json json_arch context
        end
    end
  | false -> failwith "No calling convention implemented for the given architecture"


let is_callee_saved var project =
  match !callee_saved_registers with
  | Some(register_set) -> String.Set.mem register_set (Var.name var)
  | None ->
    callee_saved_registers := Some(String.Set.of_list (get_register_list project "callee_saved"));
    String.Set.mem (Option.value_exn !callee_saved_registers) (Var.name var)


let is_parameter_register (var: Var.t) (project: Project.t) : Bool.t =
  let param_register = get_register_list project "params" in
  Option.is_some (List.find param_register ~f:(String.equal (Var.name var)))


let is_return_register (var: Var.t) (project: Project.t) : Bool.t =
  let ret_register = get_register_list project "return" in
  Option.is_some (List.find ret_register ~f:(String.equal (Var.name var)))


(** Parse a line from the dyn-syms output table of objdump. Return the name of a symbol if the symbol is an extern function name. *)
let parse_dyn_sym_line (line : string) : string option =
  let line = ref (String.strip line) in
  let str_list = ref [] in
  while Option.is_some (String.rsplit2 !line ~on:' ') do
    let (left, right) = Option.value_exn (String.rsplit2 !line ~on:' ') in
    line := String.strip left;
    str_list := right :: !str_list;
  done;
  str_list := !line :: !str_list;
  match !str_list with
  | value :: func1 :: func2 :: _ -> begin
      match ( String.strip ~drop:(fun x -> x = '0') value ) with
      | "" -> begin
          if (String.equal func1 "DF" || String.equal func2 "DF") then (
            List.last !str_list
          )
          else None
        end
      | _ -> None (* The symbol has a nonzero value, so we assume that it is not an extern function symbol. *)
    end
  | _ -> None


let parse_dyn_syms (project : Project.t) : String.Set.t =
  match !dyn_syms with
  | Some(symbol_set) -> symbol_set
  | None -> begin
    let lines = call_objdump project "--dynamic-syms" "[cwe_checker] Parsing of dynamic symbols failed:" in
    match lines with
    | _ :: _ :: _ :: _ :: tail -> (* The first four lines are not part of the table *)
      let symbol_set = String.Set.of_list (List.filter_map tail ~f:parse_dyn_sym_line) in
      dyn_syms := Some(symbol_set);
      symbol_set
    | _ ->
      dyn_syms := Some(String.Set.empty);
      String.Set.empty
  end
