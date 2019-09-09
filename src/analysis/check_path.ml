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
  let e_count = List.length (Seq.to_list (Path.edges path)) in
  if e_count = 0 then "()" else
    begin
      let format_node n = sprintf "%s" (Address_translation.translate_tid_to_assembler_address_string n tid_map) in
      let formated_start_node = format_node (get_source (Path.start path)) in
      let formated_rest_nodes = List.map (Seq.to_list @@ Path.edges path) ~f:(fun e -> format_node (get_destination e)) in
      let formated_full_path = "(" ^ formated_start_node ^ ", " ^ (String.concat ~sep:", " formated_rest_nodes) ^ ")" in
      formated_full_path
    end

let find_subfunction_name program name =
  Term.enum sub_t program
  |> Seq.find_map ~f:(fun s -> Option.some_if (contains_substring name (Sub.name s)) (Term.tid s))

let get_tids_from_cwe_hit (cwe_hit: Log_utils.CweWarning.t) =
  cwe_hit.tids

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
  | hd :: _ -> Some (Bap.Std.Tid.from_string_exn hd)

let cwe_hit_fst_addr cwe_hit =
   match get_tids_from_cwe_hit cwe_hit with
  | [] -> Bap.Std.Tid.from_string_exn "0x00"
  | hd :: _ -> Bap.Std.Tid.from_string_exn hd

let block_has_callsite blk t =
  Term.enum jmp_t blk |>
    Seq.exists ~f:(fun j ->
        match Jmp.kind j with
        | Goto _ | Ret _ | Int (_,_) -> false 
        | Call destination -> begin match Call.target destination with
                              | Direct tid -> tid = t
                              | _ -> false
                              end)

let collect_callsites program t =
  Term.enum sub_t program
  |> Seq.map ~f:(fun s -> if Term.enum blk_t s |>
                               Seq.exists ~f:(fun b -> block_has_callsite b t) then Some s else None)
  |> Seq.filter ~f:(fun s -> match s with
                             | None -> false
                             | _ -> true)
  |> Seq.map ~f:(fun s -> match s with
                          | Some s -> Term.tid s
                          | _ -> failwith "[checkpath] this should not happen.")

let sub_has_tid sub tid =
  Term.enum blk_t sub
  |> Seq.exists ~f:(fun blk -> Term.tid blk = tid || Blk.elts blk
                               |> Seq.exists ~f:(fun e -> match e with
                                                          | `Def d -> Term.tid d = tid
                                                          | `Jmp j -> Term.tid j = tid
                                                          | `Phi p -> Term.tid p = tid ))

let find_sub_tid_of_term_tid program tid =
  match tid with
  | Some t -> let s = Term.enum sub_t program
                      |> Seq.find ~f:(fun s -> sub_has_tid s t) in
              begin
                match s with
                | Some f -> Some (Term.tid f)
                | None -> printf "Could not find sub for term tid %s\n" (Tid.to_string t); None
              end
  | None -> None


let verify_one program tid_map source destination source_tid destination_tid =
  match verify source_tid destination_tid program with
           | None -> () 
           | Some p ->
              begin match p with
              | Calls p -> printf "Found path from %s to %s: %s\n" source (Address_translation.translate_tid_to_assembler_address_string (cwe_hit_fst_addr destination) tid_map) (format_path CG.Edge.src CG.Edge.dst p tid_map);
              | Sites p -> Format.printf "Found path from %s to %s: %s\n" source (Address_translation.translate_tid_to_assembler_address_string (cwe_hit_fst_addr destination) tid_map) (format_path CFG.Edge.src CFG.Edge.dst p tid_map);
              end

let find_source_sink_pathes source destination program tid_map =
  match Option.both (find_subfunction_name program source) (find_sub_tid_of_term_tid program (get_fst_tid_from_cwe_hit destination)) with
      | None -> () (*one or both functions are not utilized.*)
      | Some (callsite_tid, destination_tid) ->
         begin
           collect_callsites program callsite_tid
           |> Seq.iter ~f:(fun source_tid -> verify_one program tid_map source destination source_tid destination_tid ) 
         end
          

let check_path prog tid_map input_functions cwe_hits =
  List.iter input_functions ~f:(fun f ->
      Log_utils.debug ("Checking for input function: " ^ f);
      List.iter cwe_hits ~f:(fun h -> find_source_sink_pathes f h prog tid_map))
