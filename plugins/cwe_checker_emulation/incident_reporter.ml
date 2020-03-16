open Core_kernel
open Cwe_checker_core
open Log_utils

let version = "0.1"

(** Keeps track of reported events so that events are not reported multiple times. *)
let reported_events = ref (String.Set.empty)

(** We may want to get the number of emulated CWEs from a central point for scalability *)
let collected_locations = Hashtbl.create (module Int) ~size:4
let known_incidents = Hashtbl.of_alist_exn (module Int) [(125, "(Out-of-bounds Read)"); (787, "(Out-of-bounds Write)"); (415, "(Double Free)"); (416, "(Use After Free)")]

let cwe_incidents = ref [||]
let unknown_cwe_incidents = ref [||]

(** Builds a string of a path of addresses. *)
let build_location_path locations =
  let rec internal locations path_str =
  match locations with
  | [] -> path_str
  | hd::[] -> internal [] (path_str ^ (Printf.sprintf "0x%x" hd))
  | hd::tl -> internal tl (path_str ^ (Printf.sprintf "0x%x -> " hd)) in
  internal locations ""

(** Looks up a concrete address for an id in the location table loc_tbl. *)
let map_id_to_location id loc_tbl =
  match Hashtbl.find loc_tbl id with
  | Some loc -> loc
  | _ -> failwith "Expected location in hashtbl but failed"

(** Translates a list of incident ids to a list of concrete addresses. *)
let get_incident_locations_from_ids ids location_tbl =
  let incident_locations = ref [] in
  Sexplib__Sexp_with_layout.List.iter ids ~f:(fun id ->  incident_locations := (map_id_to_location (Sexp.to_string id) location_tbl)::(!incident_locations)); !incident_locations


let build_description (incident_str : string) (end_point : string) (paths : string list) : string =
  let pretty_paths = ref "" in
  pretty_paths := !pretty_paths^end_point^"\n";
  List.iter ~f:(fun path ->
    let clean_path = String.drop_suffix path 3 in
    pretty_paths := !pretty_paths^"\n  "^clean_path
  ) paths;
  sprintf "%s %s \n" incident_str !pretty_paths


let report_cwe _ =
  Array.iter ~f:(fun (id, loc_hash) ->
    let incident_str = (Hashtbl.find_exn known_incidents id) in
    Hashtbl.iter_keys loc_hash ~f:(fun end_point ->
      let paths = (Hashtbl.find_multi loc_hash end_point) in
      let description = build_description incident_str end_point paths in
      let other = List.map ~f:(fun path ->
        let clean_path = String.drop_suffix path 3 in
        ["path"; clean_path]
      ) paths in
      let cwe = sprintf "CWE%d" id in
      collect_cwe_warning (cwe_warning_factory cwe version ~addresses:[end_point] ~other:other description)
    )
  ) !cwe_incidents


let report_unknown_incidents _ =
  match Array.is_empty !unknown_cwe_incidents with
  | true -> ()
  | false -> begin
    print_endline "Unknown incidents:";
    Array.iter ~f:(fun (path, inc) ->
      let description = inc ^ " " ^ path in
      collect_cwe_warning (cwe_warning_factory inc version ~other:[["path"; path]] description)
    ) !unknown_cwe_incidents
    end


let collect_known_incidents (cwe : int) (execution_path : string) =
  Hashtbl.add_multi collected_locations ~key:cwe ~data:(String.rsplit2_exn execution_path ~on:' ')


let collect_unknown_incidents (path_inc : string * string) =
  unknown_cwe_incidents := Array.append !unknown_cwe_incidents [|path_inc|]


let parse_reports _ =
  Hashtbl.iter_keys collected_locations ~f:(fun id ->
    let loc_hashtbl = Hashtbl.create (module String) ~size:3 in
    List.iter ~f:(fun (path, end_point) ->
      Hashtbl.add_multi loc_hashtbl ~key:end_point ~data:path
    ) (Hashtbl.find_multi collected_locations id);
    cwe_incidents := Array.append !cwe_incidents [|(id, loc_hashtbl)|]
  )


(** Reports an incident. *)
let report incident location_tbl =
  match incident with
  | name::ids ->
    begin
      let incident_locations = get_incident_locations_from_ids ids location_tbl in
      let filtered_locs = Int.Set.to_list (Int.Set.of_list (List.concat incident_locations)) in
      let incident_str = Sexp.to_string name in
      let location_path = build_location_path filtered_locs in
      if Set.mem !reported_events location_path
      then
        ()
      else
        begin
          reported_events := Set.add !reported_events location_path;
            match incident_str with
              | "memcheck-out-of-bound" -> collect_known_incidents 125 location_path
              | "memcheck-double-release" -> collect_known_incidents 415 location_path
              | "memcheck-use-after-release" -> collect_known_incidents 416 location_path
              | _ -> collect_unknown_incidents (location_path, incident_str)
          end
    end
  | __ -> failwith "Strange incident sexp encountered"
