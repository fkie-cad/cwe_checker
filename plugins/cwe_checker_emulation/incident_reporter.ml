open Core_kernel
open Cwe_checker_core

let version = "0.1"

(** Keeps track of reported events so that events are not reported multiple times. *)
let reported_events = ref (String.Set.empty)

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

let report_cwe_125 location_path = 
      Log_utils.warn "[CWE125] {%s} (Out-of-bounds Read) %s" version location_path;
      Log_utils.warn "[CWE787] {%s} (Out-of-bounds Write) %s" version location_path

let report_cwe_415 location_path =
  Log_utils.warn "[CWE415] {%s} (Double Free) %s" version location_path

let report_cwe_416 location_path =
  Log_utils.warn "[CWE416] {%s} (Use After Free) %s" version location_path

let report_cwe_unknown location_path incident_str =
  Log_utils.warn "[CWE UNKNOWN] {%s} (%s) %s" version incident_str location_path


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
            | "memcheck-out-of-bound" -> report_cwe_125 location_path
            | "memcheck-double-release" -> report_cwe_415 location_path
            | "memcheck-use-after-release" -> report_cwe_416 location_path
            | _ -> report_cwe_unknown location_path incident_str
          end
    end
  | __ -> failwith "Strange incident sexp encountered"
