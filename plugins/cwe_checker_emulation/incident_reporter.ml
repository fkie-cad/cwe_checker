open Core_kernel

let version = "0.1"

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

let report_cwe_125 locs =
  Log_utils.warn "[CWE125] {%s} (Out-of-bounds Read) %s" version (build_location_path locs)

let report_cwe_415 locs =
  Log_utils.warn "[CWE415] {%s} (Double Free) %s" version (build_location_path locs)

let report_cwe_416 locs =
  Log_utils.warn "[CWE416] {%s} (Use After Free) %s" version (build_location_path locs)

let report_cwe_unknown locs incident_str =
  Log_utils.warn "[CWE UNKNOWN] {%s} (%s) %s" version incident_str (build_location_path locs)


(** Reports an incident. *)
let report incident location_tbl =
  match incident with
  | name::ids ->
    begin
      let incident_locations = get_incident_locations_from_ids ids location_tbl in 
      let filtered_locs = Int.Set.to_list (Int.Set.of_list (List.concat incident_locations)) in
      let incident_str = Sexp.to_string name in
      match incident_str with
      (* TODO: we report an out-of-bounds read but actually it could also be
         an out-of-bound write. Find out how to distinguish between them. *)
      | "memcheck-out-of-bound" -> report_cwe_125 filtered_locs
      | "memcheck-double-release" -> report_cwe_415 filtered_locs
      (* TODO: check if there are duplicate events and remove duplicates! *)
      | "memcheck-use-after-release" -> report_cwe_416 filtered_locs
      | _ -> report_cwe_unknown filtered_locs incident_str
    end
  | __ -> failwith "Strange incident sexp encountered"
