open Core_kernel.Std
open Bap.Std
open Graphlib.Std
open Format
open Yojson.Basic.Util

include Self()

let known_modules = [(Cwe_190.name, Cwe_190.version);
                     (Cwe_215.name, Cwe_215.version);
                     (Cwe_243.name, Cwe_243.version);
                     (Cwe_248.name, Cwe_248.version);
                     (Cwe_332.name, Cwe_332.version);
                     (Cwe_367.name, Cwe_367.version);
                     (Cwe_426.name, Cwe_426.version);
                     (Cwe_467.name, Cwe_467.version);
                     (Cwe_476.name, Cwe_476.version);
                     (Cwe_457.name, Cwe_457.version);
                     (Cwe_676.name, Cwe_676.version);
                     (Cwe_782.name, Cwe_782.version)]

let build_version_sexp () =
  List.map known_modules ~f:(fun (name, version) -> Format.sprintf "(\"%s\" \"%s\")" name version)
  |> String.concat ~sep:" "

let print_module_versions () =
  Log_utils.info
    "[cwe_checker] module_versions: (%s)"
    (build_version_sexp ())

(** Extracts the symbols to check for from json document.
An example looks like this:
"CWE467": {
	"symbols": ["strncmp", "malloc",
		    "alloca", "_alloca", "strncat", "wcsncat",
		    "strncpy", "wcsncpy", "stpncpy", "wcpncpy",
		    "memcpy", "wmemcpy", "memmove", "wmemmove", "memcmp", "wmemcmp"],
	"_comment": "any function that takes something of type size_t could be a possible candidate."
    }, *)
let get_symbols_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "symbols"
  |> flatten
  |> List.map ~f:to_string

let init_cwe_190 json project program tid_address_map =
  let symbols = get_symbols_from_json json "CWE190" in
  Cwe_190.check_cwe program project tid_address_map symbols

let init_cwe_215 json project program tid_address_map =
  Cwe_215.check_cwe project

let init_cwe_243 json project program tid_address_map =
  [json]
  |> filter_member "CWE243"
  |> filter_member "chroot_pathes"
  |> flatten
  |> List.map ~f:(fun l -> List.map (to_list l) ~f:to_string)
  |> Cwe_243.check_cwe program project tid_address_map

  let init_cwe_248 json project program tid_address_map =
    Cwe_248.check_cwe program tid_address_map

let init_cwe_332 json project program tid_address_map =
  (* TODO: read config. *)
  Cwe_332.check_cwe program project tid_address_map

let init_cwe_367 json project program tid_address_map =
  (* TODO: read config. *)
  Cwe_367.check_cwe program project tid_address_map

let init_cwe_426 json project program tid_address_map =
  (* TODO: read config. *)
  let symbols = ["setresgid"; "setresuid"; "setuid"; "setgid"; "seteuid"; "setegid"] in
  Cwe_426.check_cwe program project tid_address_map symbols

let init_cwe_457 json project program tid_address_map =
   Cwe_457.check_cwe program project tid_address_map

let init_cwe_467 json project program tid_address_map =
  let symbols = get_symbols_from_json json "CWE467" in
  Cwe_467.check_cwe program project tid_address_map symbols

let init_cwe_476 json project program tid_address_map =
   let symbols = get_symbols_from_json json "CWE476" in
   Cwe_476.check_cwe program project tid_address_map symbols

let init_cwe_676 json project program tid_address_map =
  let symbols = get_symbols_from_json json "CWE676" in
  Cwe_676.check_cwe program tid_address_map symbols

let init_cwe_782 json project program tid_address_map =
  (* TODO: read config and hand over symbols from man ioctl *)
  let symbols = [] in
  Cwe_782.check_cwe program project tid_address_map symbols

let partial_run project config modules =
  (* IMPLEMENT ME: checkout how to dispatch ocaml modules dynamically *)
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in
  Log_utils.info "[cwe_checker] Just running a partial update of %s." modules

let full_run project config =
  let program = Project.program project in
  let tid_address_map = Address_translation.generate_tid_map program in
  let json = Yojson.Basic.from_file config in
  begin
    init_cwe_190 json project program tid_address_map;
    init_cwe_215 json project program tid_address_map;
    init_cwe_243 json project program tid_address_map;
    init_cwe_248 json project program tid_address_map;
    init_cwe_332 json project program tid_address_map;
    init_cwe_367 json project program tid_address_map;
    init_cwe_426 json project program tid_address_map;
    init_cwe_457 json project program tid_address_map;
    init_cwe_467 json project program tid_address_map;
    init_cwe_476 json project program tid_address_map;
    init_cwe_676 json project program tid_address_map;
    init_cwe_782 json project program tid_address_map
  end

let main config module_versions partial_update project =
  Log_utils.set_log_level Log_utils.DEBUG;
  Log_utils.set_output stdout;
  Log_utils.color_on ();

  if module_versions then
    begin
      print_module_versions ()
    end
  else
    begin
      if config = "" then
        Log_utils.error "[cwe_checker] No configuration file provided! Aborting..."
      else
        begin
          if partial_update = "" then
            full_run project config
          else
            partial_run project config partial_update
        end
    end

module Cmdline = struct
  open Config
  let config = param string "config" ~doc:"Path to configuration file."
  let module_versions = param bool "module_versions" ~doc:"Prints out the version numbers of all known modules."
  let partial_update = param string "partial" ~doc:"Comma separated list of modules to apply on binary."
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' ~deps:["callsites"] (main !!config !!module_versions !!partial_update))
  let () = manpage [
                          `S "DESCRIPTION";
                          `P
                            "This plugin checks various CWEs such as Insufficient Entropy in PRNG (CWE-332) or Use of Potentially Dangerous Function (CWE-676)"
                        ]
end
