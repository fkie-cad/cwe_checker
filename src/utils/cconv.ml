
open Bap.Std
open Core_kernel.Std

    (* TODO: add thumb *)

let dyn_syms = ref None

(** Return a list of registers that are callee-saved. *)
let callee_saved_register_list project =
  let arch = Project.arch project in
  match arch with
  | `x86_64 -> (* System V ABI *)
    "RBX" :: "RSP" :: "RBP" :: "R12" :: "R13" :: "R14" :: "R15" :: []
  | `x86_64 -> (* Microsoft x64 calling convention *) (* TODO: How to distinguish from System V? For the time being, only use the System V ABI, since it saves less registers. *)
    "RBX" :: "RBP" :: "RDI" :: "RSI" :: "RSP" :: "R12" :: "R13" :: "R14" :: "R15" :: []
  | `x86 -> (* Both Windows and Linux save the same registers *)
    "EBX" :: "ESI" :: "EDI" :: "EBP" :: []
  | `armv4 | `armv5 | `armv6 | `armv7
  | `armv4eb | `armv5eb | `armv6eb | `armv7eb -> (* ARM 32bit. R13 and SP are both names for the stack pointer. *)
    "R4" :: "R5" :: "R6" :: "R7" :: "R8" :: "R9" :: "R10" :: "R11" :: "R13" :: "SP" :: []
  | `aarch64 | `aarch64_be -> (* ARM 64bit *) (* TODO: This architecture is not contained in the acceptance tests yet? *) (* TODO: check, whether bap uses another name than SP for the stack register. *)
    "X19" :: "X20" :: "X21" :: "X22" :: "X23" :: "X24" :: "X25" :: "X26" :: "X27" :: "X28" :: "X29" :: "SP" :: []
  | `ppc (* 32bit PowerPC *) (*  TODO: add floating point registers. *) (* TODO: add CR2, CR3, CR4. Test their representation in bap first. *)
  | `ppc64 | `ppc64le -> (* 64bit PowerPC *)
    "R14" :: "R15" :: "R16" :: "R17" :: "R18" :: "R19" :: "R20" :: "R21" :: "R22" :: "R23" ::
    "R24" :: "R25" :: "R26" :: "R27" :: "R28" :: "R29" :: "R30" :: "R31" :: "R1" :: "R2" :: []
  | `mips | `mips64 | `mips64el | `mipsel -> (* TODO: find a real world example to test this out *) (* TODO: S8 and FP should be the same register, find out which name bap uses. *)
    "S0" :: "S1" :: "S2" :: "S3" :: "S4" :: "S5" :: "S6" :: "S7" :: "S8" :: "GP" :: "SP" :: "FP" :: []
  | _ -> failwith "No calling convention implemented for the given architecture."

let is_callee_saved var project =
  let register_list = callee_saved_register_list project in
  List.exists register_list ~f:(fun elem -> elem = (Var.name var))

(** Parse a line from the dyn-syms output table of readelf. Return the name of a symbol if the symbol is an extern function name. *)
let parse_dyn_sym_line line =
  let line = ref (String.strip line) in
  let str_list = ref [] in
  while Option.is_some (String.rsplit2 !line ~on:' ') do
    let (left, right) = Option.value_exn (String.rsplit2 !line ~on:' ') in
    line := String.strip left;
    str_list := right :: !str_list;
  done;
  match !str_list with
  | _ :: value :: _ :: "FUNC" :: _ :: _ :: _ :: name :: [] -> begin
      match ( String.strip ~drop:(fun x -> x = '0') value, String.lsplit2 name ~on:'@') with
      | ("", Some(left, _)) -> Some(left)
      | ("", None) -> Some(name)
      | _ -> None (* The symbol has a nonzero value, so we assume that it is not an extern function symbol. *)
    end
  | _ -> None

let parse_dyn_syms project =
  match !dyn_syms with
  | Some(symbol_set) -> symbol_set
  | None ->
    match Project.get project filename with
    | None -> failwith "[CWE-checker] Project has no file name."
    | Some(fname) -> begin
        let cmd = Format.sprintf "readelf --dyn-syms %s" fname in
        try
          let in_chan = Unix.open_process_in cmd in
          let lines = In_channel.input_lines in_chan in
          let () = In_channel.close in_chan in begin
            match lines with
            | _ :: _ :: _ :: tail -> (* The first three lines are not part of the table *)
              let symbol_set = String.Set.of_list (List.filter_map tail ~f:parse_dyn_sym_line) in
              dyn_syms := Some(symbol_set);
              symbol_set
            | _ ->
              dyn_syms := Some(String.Set.empty);
              String.Set.empty              (*  *)
          end
        with
          Unix.Unix_error (e,fm,argm) ->
          failwith (Format.sprintf "[CWE-checker] Parsing of dynamic symbols failed: %s %s %s" (Unix.error_message e) fm argm)
      end
