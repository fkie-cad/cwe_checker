open Core_kernel
open Bap.Std
open Graphlib.Std
open Format

include Self()

module CG = Graphs.Callgraph
module CFG = Graphs.Tid

type proof =
  | Calls of CG.edge path
  | Sites of CFG.edge path

(** Taken from https://stackoverflow.com/questions/8373460/substring-check-in-ocaml *)
let contains_substring search target =
    String.substr_index ~pattern:search target <> None

let format_path get_source get_destination path tid_map =
  let format_node n = sprintf "%s" (Address_translation.translate_tid_to_assembler_address_string n tid_map) in
  let formated_start_node = format_node (get_source (Path.start path)) in
  let formated_rest_nodes = List.map (Seq.to_list @@ Path.edges path) ~f:(fun e -> format_node (get_destination e)) in
  let formated_full_path = "(" ^ formated_start_node ^ ", " ^ (String.concat ~sep:", " formated_rest_nodes) ^ ")" in
  formated_full_path

let find_subfunction_name program name =
  Term.enum sub_t program
  |> Seq.find_map ~f:(fun s -> Option.some_if (contains_substring name (Sub.name s)) (Term.tid s))

let get_tids_from_cwe_hit (cwe_hit: Log_utils.CweWarning.t) =
  cwe_hit.tids

(* let collect_addresses_sub sub = 
 *   Term.enum blk_t sub |> Seq.concat_map ~f:(fun b -> Seq.map (Blk.elts b) ~f:(fun e -> match e with
 *                                                                             | `Def d -> Term.tid d
 *                                                                             | `Jmp j -> Term.tid j
 *                                                                             | `Phi p -> Term.tid p)) *)

(* (\** At the moment we are only considering the first address of a hit. This is where the CWE starts
 *  and this is where we wish to find a path to. *\)
 * let contains_sub_cwe_hit sub cwe_hit =
 *   match get_tids_from_cwe_hit cwe_hit with
 *   | [] -> false
 *   | hd :: _ -> let addrs = collect_addresses_sub sub in
 *                Seq.exists addrs ~f:(fun a -> (Address_translation.tid_to_string a) = hd) *)

(* let find_subfunction_cwe_hit program cwe_hit =
 *   Term.enum sub_t program
 *   |> Seq.find_map ~f:(fun s -> Option.some_if (contains_sub_cwe_hit s cwe_hit) (Term.tid s)) *)

let reaches cg callee target =
  Graphlib.is_reachable (module CG) cg callee target

(* ignores indirect calls and jumps as well as return statements and interupts *)
let callsites cg target sub =
  Term.enum blk_t sub |>
  Seq.concat_map ~f:(fun blk ->
      Term.enum jmp_t blk |> Seq.filter_map ~f:(fun j ->
          match Jmp.kind j with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call destination -> begin match Call.target destination with
            | Direct tid when reaches cg tid target -> Some (Term.tid blk)
            | _ -> None
                                end))

let verify source destination program : proof option =
  printf "HERE verify\n";
  let cg = Program.to_graph program in
  match Graphlib.shortest_path (module CG) cg source destination with
  | Some path -> Some (Calls path)
  | None ->
     Term.enum sub_t program |> Seq.find_map ~f:(fun sub ->
        let g = Sub.to_graph sub in
        Seq.find_map (callsites cg source sub) ~f:(fun sc ->
            Seq.find_map (callsites cg destination sub) ~f:(fun dc ->
                if Tid.equal sc dc then None
                else Graphlib.shortest_path (module CFG) g sc dc))) |>
    Option.map ~f:(fun p -> Sites p)

let get_fst_tid_from_cwe_hit (cwe_hit: Log_utils.CweWarning.t) =
  match cwe_hit.tids with
  | [] -> None
  | hd :: _ -> printf "HD: %s\n" hd; Some (Bap.Std.Tid.from_string_exn hd)

let cwe_hit_fst_addr_to_str cwe_hit =
   match get_tids_from_cwe_hit cwe_hit with
  | [] -> ""
  | hd :: _ -> hd

let find_source_sink_pathes source destination program tid_map =
  let a = find_subfunction_name program source in
  match a with
  | None -> (* printf "NOT FOUND: %s\n" source *) ()
  | Some _ -> printf "FOUND IT: %s\n" source
  ;
  match Option.both (find_subfunction_name program source) (get_fst_tid_from_cwe_hit destination) with
      | None -> () (*one or both functions are not utilized.*)
      | Some (source_tid, destination_tid) -> printf "HUNTING for path from %s to %s\n" (Bap.Std.Tid.to_string source_tid) (Bap.Std.Tid.to_string destination_tid); match verify source_tid destination_tid program with
        | None -> () (*No path between the two APIs found*)
        | Some p ->
          begin match p with
          | Calls p -> Format.printf "(%s,%s);%s" source (cwe_hit_fst_addr_to_str destination) (format_path CG.Edge.src CG.Edge.dst p tid_map);
                       Format.print_newline ()
          | Sites p -> Format.printf "(%s,%s);%s" source (cwe_hit_fst_addr_to_str destination) (format_path CFG.Edge.src CFG.Edge.dst p tid_map);
                       Format.print_newline ()
          end


let check_path prog tid_map input_functions cwe_hits =
  List.iter input_functions ~f:(fun f ->
      List.iter cwe_hits ~f:(fun h -> find_source_sink_pathes f h prog tid_map))
