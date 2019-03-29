open Core_kernel
open Bap.Std
open Bap_primus.Std
open Bap_future.Std
open Graphlib.Std
open Monads.Std
open Format
open Ppx_jane

include Self()

let version = "0.1"

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

(** Looks up a concrete address for an id in the location table loc_tbl. *)
let map_id_to_location id loc_tbl =
  match Hashtbl.find loc_tbl id with
  | Some loc -> loc
  | _ -> failwith "Expected location in hashtbl but failed"

(** Builds a string of a path of addresses. *)
let build_location_path locations =
  let rec internal locations path_str =
  match locations with
  | [] -> path_str
  | hd::[] -> internal [] (path_str ^ (Printf.sprintf "0x%x" hd))
  | hd::tl -> internal tl (path_str ^ (Printf.sprintf "0x%x -> " hd)) in
  internal locations ""

(** Translates a list of incident ids to a list of concrete addresses. *)
let get_incident_locations_from_ids ids location_tbl =
  let incident_locations = ref [] in
      Sexplib__Sexp_with_layout.List.iter ids ~f:(fun id ->  incident_locations := (map_id_to_location (Sexp.to_string id) location_tbl)::(!incident_locations)); !incident_locations

let report_cwe_415 locs =
  Log_utils.warn "[CWE415] {%s} (Double Free) %s" version (build_location_path locs)

let report_cwe_unknown locs incident_str =
  Log_utils.warn "[CWE UNKNOWN] {%s} (%s) %s" version incident_str (build_location_path locs)

(** Reports an incident. *)
let report_incident incident location_tbl =
  match incident with
  | name::ids ->
    begin
      let incident_locations = get_incident_locations_from_ids ids location_tbl in 
      let filtered_locs = Int.Set.to_list (Int.Set.of_list (List.concat incident_locations)) in
      let incident_str = Sexp.to_string name in
      match incident_str with
      | "memcheck-double-release" -> report_cwe_415 filtered_locs
      | _ -> report_cwe_unknown filtered_locs incident_str
    end
  | __ -> failwith "Strange incident sexp encountered"

(** Reports events to the user. *)
let report_events _ =
  let location_tbl = Hashtbl.create (module String) in
  let incident_list = ref [] in
  Array.iter ~f:(fun (p, ev) ->
      begin
        match ev with
        |  Sexp.Atom _ -> failwith "Sexp.Atom not expected in report_events."
        |  Sexp.List [Sexp.Atom location_id; Sexp.List location_list] -> Hashtbl.add location_tbl location_id (convert_location_list location_list);()
        |  Sexp.List incident -> report_incident incident location_tbl
      end) !collected_events

(** Just adds the observed Primus events to the collected_events array. *)
let collect_events p ev =
  collected_events := Array.append !collected_events [|(p, ev)|]

(* Most functions beyond here have been taken and adjusted from BAP's Primus plugins*)

let string_of_name = function
  | `symbol s -> s
  | `tid t -> Tid.to_string t
| `addr x -> Addr.string_of_value x

(** Collects all entry points of the program. *)
let entry_point_collector = object
  inherit [tid list] Term.visitor
  method! enter_term _ t entries =
    if Term.has_attr t Sub.entry_point
    then Term.tid t :: entries
    else entries
  end

(** Wrapper function around entry_point_collector. *)
let entry_points prog =
  entry_point_collector#run prog []

(** Collects all subroutines of the program that
that are not an entry point. *)
let all_subroutines prog =
  let entries = entry_points prog in
  let non_entry =
    let roots = Tid.Set.of_list entries in
    fun t -> if Set.mem roots t then None else Some (`tid t) in
  List.map entries ~f:(fun t -> `tid t) @
  Seq.to_list @@
  Seq.filter_map ~f:non_entry @@
  Graphlib.reverse_postorder_traverse (module Graphs.Callgraph) @@
    Program.to_graph prog

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
- for all subroutins we fork a Primus machine
- all monitored events are collected globally
- after the last Primus machine has terminated we report all observed incidents *)
let main {Config.get=(!)} proj =
  Primus.Machine.add_component (module Monitor);
  begin
  let targets =  all_subroutines (Project.program proj) in
  Main.run ~envp:[||] ~args:[||] proj (run targets) |> function
  | (Primus.Normal,proj)
  | (Primus.Exn Primus.Interpreter.Halt,proj) ->
     info "Ok, we've terminated normally";
  | (Primus.Exn exn,proj) ->
     info "program terminated by a signal: %s" (Primus.Exn.to_string exn);
  end;
  report_events ();
  proj

(** At the moment this plugin depends due to Primus on the plugin
trivial-condition-form. *)
 let deps = [
  "trivial-condition-form"
]

let () =
  Config.when_ready (fun conf -> Project.register_pass ~deps (main conf))
