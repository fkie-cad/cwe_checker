open Core_kernel
open Bap.Std
open Bap_primus.Std
open Bap_future.Std
open Graphlib.Std
open Monads.Std
open Format
open Ppx_jane
open Cwe_checker_core

include Self()

let pp_id = Monad.State.Multi.Id.pp

module Machine = struct
  type 'a m = 'a
  include Primus.Machine.Make(Monad.Ident)
end
open Machine.Syntax

module Main = Primus.Machine.Main(Machine)
module Interpreter = Primus.Interpreter.Make(Machine)
module Linker = Primus.Linker.Make(Machine)
module Env = Primus.Env.Make(Machine)
module Lisp = Primus.Lisp.Make(Machine)
module Eval = Primus.Interpreter.Make(Machine)

(** this array collects the observed primus events*)
let collected_events = ref ([||])

(** Converts a hexadecimal string representation of
an address to an integer. *)
let convert_location loc =
  match (Str.split (Str.regexp ":") loc) with
  | fst::snd::[] -> Int.of_string ("0x" ^ snd)
  | _ -> failwith "Could not parse location"

(** Converts a list of hexadecimal strings to a
list of integers. *)
let convert_location_list loc_list =
  let locs = ref [] in
  Sexplib__Sexp_with_layout.List.iter loc_list ~f:(fun x -> locs := (convert_location @@ Sexp.to_string x)::(!locs));
  !locs

(** Analyze events and report to the user. *)
let analyze_events _ =
  let location_tbl = Hashtbl.create (module String) in
  Array.iter ~f:(fun (p, ev) ->
      begin
        match ev with
        |  Sexp.Atom _ -> failwith "Sexp.Atom not expected in report_events."
        |  Sexp.List [Sexp.Atom location_id; Sexp.List location_list] -> Hashtbl.add_exn location_tbl location_id (convert_location_list location_list)
        |  Sexp.List incident -> Incident_reporter.report incident location_tbl
      end) !collected_events

(** Just adds the observed Primus events to the collected_events array. *)
let collect_events p ev =
  collected_events := Array.append !collected_events [|(p, ev)|]

(* Most functions beyond here have been taken and adjusted from BAP's Primus plugins*)

let string_of_name = function
  | `symbol s -> s
  | `tid t -> Tid.to_string t
| `addr x -> Addr.string_of_value x

(** Executes/forks another Primus machine. *)
let exec x =
  Machine.current () >>= fun cid ->
  info "Fork %a: starting from the %s entry point"
    pp_id cid (string_of_name x);
  Machine.catch (Linker.exec x)
    (fun exn ->
       info "execution from %s terminated with: %s "
         (string_of_name x)
         (Primus.Exn.to_string exn);
       Machine.return ())

let rec run = function
  | [] ->
    info "all toplevel machines done, halting";
    Eval.halt >>=
    never_returns
  | x :: xs ->
    Machine.current () >>= fun pid ->
    Machine.fork ()    >>= fun () ->
    Machine.current () >>= fun cid ->
    if pid = cid
    then run xs
    else
      exec x >>= fun () ->
      Eval.halt >>=
      never_returns

(** Checks if a certain Primus.Observation.Provider is equal
    to a string like 'incident'. *)
let has_name name p =
  Primus.Observation.Provider.name p = name

(** Register a monitor. *)
let monitor_provider name ps =
  Primus.Observation.list_providers () |>
  List.find ~f:(has_name name) |> function
  | None -> invalid_argf "An unknown observation provider `%s'" name ()
  | Some p -> p :: ps

let parse_monitors =
  List.fold ~init:[] ~f:(fun ps name -> monitor_provider name ps)

(** Register monitors for 'incident' related events. *)
module Monitor(Machine : Primus.Machine.S) = struct
    open Machine.Syntax

    let init () =
      parse_monitors ["incident"; "incident-location"] |>
      List.iter ~f:(fun m ->
          info "monitoring %s" (Primus.Observation.Provider.name m);
          Stream.observe (Primus.Observation.Provider.data m) (collect_events m));
      Machine.return ()
end

(** Main logic of program:
- we monitor all 'incident' related events
- for all subroutines we fork a Primus machine
- all monitored events are collected globally
- after the last Primus machine has terminated we report all observed incidents *)
let main json_output file_output proj =
  print_endline "INFO: The emulation based checks in this plugin have been deprecated. Please look at https://github.com/BinaryAnalysisPlatform/bap-toolkit for an alternative." ;
  Primus.Machine.add_component (module Monitor);
  begin
  let prog = (Project.program proj) in
  let targets = Seq.to_list @@ Seq.map (Term.enum sub_t prog) ~f:(fun x -> `tid (Term.tid x)) in
  Main.run ~envp:[||] ~args:[||] proj (run targets) |> function
  | (Primus.Normal,proj)
  | (Primus.Exn Primus.Interpreter.Halt,proj) ->
     info "Ok, we've terminated normally";
  | (Primus.Exn exn,proj) ->
     info "program terminated by a signal: %s" (Primus.Exn.to_string exn);
  end;
  analyze_events ();
  Incident_reporter.parse_reports ();
  Incident_reporter.report_cwe ();
  Incident_reporter.report_unknown_incidents ();
  if json_output then
    begin
      match Project.get proj filename with
      | Some fname -> Log_utils.emit_json fname file_output
      | None -> Log_utils.emit_json "" file_output
    end
  else
    Log_utils.emit_native file_output


module Cmdline = struct
  open Config
  let json_output = flag "json" ~doc:"Outputs the result as JSON."
  let file_output = param string "out" ~doc:"Path to output file."
  let () = when_ready (fun ({get=(!!)}) -> Project.register_pass' ~deps:["trivial-condition-form"] (main !!json_output !!file_output))
  let () = manpage [
               `S "DESCRIPTION";
               `P "This plugin utilizes symbolic execution to find CWEs like Double Free (CWE415) or Use After Free (CWE416)."]
end
