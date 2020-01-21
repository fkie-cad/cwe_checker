
open Bap.Std
open Core_kernel

let dyn_syms = ref None

let callee_saved_registers = ref None

(** Return a list of registers that are callee-saved.
    TODO: At least ARMv7 and PPC have floating point registers that are callee saved. Check their names in bap and then add them. *)
let callee_saved_register_list project =
  let arch = Project.arch project in
  match arch with
  | `x86_64 -> (* System V ABI *)
      "RBX" :: "RSP" :: "RBP" :: "R12" :: "R13" :: "R14" :: "R15" :: []
  (* Microsoft x64 calling convention. Unused at the moment, since Windows binaries are not yet supported.
  | `x86_64 -> (* Microsoft x64 calling convention *)
     "RBX" :: "RBP" :: "RDI" :: "RSI" :: "RSP" :: "R12" :: "R13" :: "R14" :: "R15" :: []
  *)
  | `x86 -> (* Both Windows and Linux save the same registers *)
    "EBX" :: "ESI" :: "EDI" :: "EBP" :: []
  | `armv4 | `armv5 | `armv6 | `armv7
  | `armv4eb | `armv5eb | `armv6eb | `armv7eb
  | `thumbv4 | `thumbv5 | `thumbv6 | `thumbv7
  | `thumbv4eb | `thumbv5eb | `thumbv6eb | `thumbv7eb -> (* ARM 32bit. R13 and SP are both names for the stack pointer. *)
    "R4" :: "R5" :: "R6" :: "R7" :: "R8" :: "R9" :: "R10" :: "R11" :: "R13" :: "SP" :: []
  | `aarch64 | `aarch64_be -> (* ARM 64bit *) (* TODO: This architecture is not contained in the acceptance tests yet? *)
    "X19" :: "X20" :: "X21" :: "X22" :: "X23" :: "X24" :: "X25" :: "X26" :: "X27" :: "X28" :: "X29" :: "SP" :: []
  | `ppc (* 32bit PowerPC *) (*  TODO: add floating point registers. *) (* TODO: add CR2, CR3, CR4. Test their representation in bap first. *)
  | `ppc64 | `ppc64le -> (* 64bit PowerPC *)
    "R14" :: "R15" :: "R16" :: "R17" :: "R18" :: "R19" :: "R20" :: "R21" :: "R22" :: "R23" ::
    "R24" :: "R25" :: "R26" :: "R27" :: "R28" :: "R29" :: "R30" :: "R31" :: "R1" :: "R2" :: []
  | `mips | `mips64 | `mips64el | `mipsel -> (* S8 and FP are the same register. bap uses FP, S8 is left there just in case. *)
    "S0" :: "S1" :: "S2" :: "S3" :: "S4" :: "S5" :: "S6" :: "S7" :: "S8" :: "GP" :: "SP" :: "FP" :: []
  | _ -> failwith "No calling convention implemented for the given architecture."

let is_callee_saved var project =
  match !callee_saved_registers with
  | Some(register_set) -> String.Set.mem register_set (Var.name var)
  | None ->
    callee_saved_registers := Some(String.Set.of_list (callee_saved_register_list project));
    String.Set.mem (Option.value_exn !callee_saved_registers) (Var.name var)

(** Return a list of all registers that may hold function arguments. *)
let get_parameter_register_list (project: Project.t) : String.t List.t =
  let architecture = Project.arch project in
  match architecture with
  | `x86 ->
      [] (* TODO: This is the value for the standard C calling convention. But it is incorrect for some of the other calling conventions for x86! *)
  | `x86_64 -> (* System V ABI. TODO: Floationg Point registers are mising! TODO: Microsoft calling convention uses different register. *)
      "RDI" :: "RSI" :: "RDX" :: "RCX" :: "R8" :: "R9" :: []
  | `armv4 | `armv5 | `armv6 | `armv7
  | `armv4eb | `armv5eb | `armv6eb | `armv7eb
  | `thumbv4 | `thumbv5 | `thumbv6 | `thumbv7
  | `thumbv4eb | `thumbv5eb | `thumbv6eb | `thumbv7eb ->
      "R0" :: "R1" :: "R2" :: "R3" :: []
  | `aarch64 | `aarch64_be -> (* ARM 64bit *)
      "X0" :: "X1" :: "X2" :: "X3" :: "X4" :: "X5" :: "X6" :: "X7" :: []
  | `ppc (* 32bit PowerPC *) (* TODO: add floating point register! *)
  | `ppc64 | `ppc64le -> (* 64bit PowerPC *)
      "R3" :: "R4" :: "R5" :: "R6" :: "R7" :: "R8" :: "R9" :: "R10" :: []
  | `mips | `mips64 | `mips64el | `mipsel -> (* TODO: MIPS has also a calling convention with less arguments. TODO: check whether BAP actually uses A4-A7 as register names or gives them different names *)
      "A0" :: "A1" :: "A2" :: "A3" :: "A4" :: "A5" :: "A6" :: "A7" :: []
  | _ -> failwith "No calling convention implemented for the given architecture"

let is_parameter_register (var: Var.t) (project: Project.t) : Bool.t =
  let param_register = get_parameter_register_list project in
  Option.is_some (List.find param_register ~f:(String.equal (Var.name var)))

(** Return all registers that may contain return values of function calls *) (* TODO: Add Floating Point register! *)
let get_return_register_list (project: Project.t) : String.t List.t =
  let architecture = Project.arch project in
  match architecture with
  | `x86 ->
      "EAX" :: []
  | `x86_64 -> (* System V ABI *)
      "RAX" :: "RDX" :: []
  | `armv4 | `armv5 | `armv6 | `armv7
  | `armv4eb | `armv5eb | `armv6eb | `armv7eb
  | `thumbv4 | `thumbv5 | `thumbv6 | `thumbv7
  | `thumbv4eb | `thumbv5eb | `thumbv6eb | `thumbv7eb ->
      "R0" :: "R1" :: "R2" :: "R3" :: []
  | `aarch64 | `aarch64_be -> (* ARM 64bit *)
      "X0" :: "X1" :: "X2" :: "X3" :: "X4" :: "X5" :: "X6" :: "X7" :: []
  | `ppc (* 32bit PowerPC *) (* TODO: add floating point register! *)
  | `ppc64 | `ppc64le -> (* 64bit PowerPC *)
      "R3" :: "R4" :: []
  | `mips | `mips64 | `mips64el | `mipsel ->
      "V0" :: "V1" :: []
  | _ -> failwith "No calling convention implemented for the given architecture"

let is_return_register (var: Var.t) (project: Project.t) : Bool.t =
  let ret_register = get_return_register_list project in
  Option.is_some (List.find ret_register ~f:(String.equal (Var.name var)))

(** Parse a line from the dyn-syms output table of readelf. Return the name of a symbol if the symbol is an extern function name. *)
let parse_dyn_sym_line line =
  let line = ref (String.strip line) in
  let str_list = ref [] in
  while Option.is_some (String.rsplit2 !line ~on:' ') do
    let (left, right) = Option.value_exn (String.rsplit2 !line ~on:' ') in
    line := String.strip left;
    str_list := right :: !str_list;
  done;
  str_list := !line :: !str_list;
  match !str_list with
  | _ :: value :: _ :: "FUNC" :: _ :: _ :: _ :: name :: _ -> begin
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
