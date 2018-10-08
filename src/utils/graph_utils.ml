open Core_kernel.Std
open Bap.Std
open Graphlib.Std

type path = {
  start_node: Bap.Std.tid;
  nodes: Bap.Std.tid array;
  end_node: Bap.Std.tid;
}

let get_entry_blk_of_sub sub =
  match Term.first blk_t sub with
  | Some blk -> blk
  | _ -> failwith "Could not determine first block of sub."

let print_path p =
  Format.printf "%s\n" (Array.fold p.nodes ~init:"" ~f:(fun acc n -> acc ^ " -> " ^ (Tid.to_string n)))

let print_path_length p =
  Format.printf "%d\n" (Array.length p.nodes)

(* ToDo: remove *)
let print_current_edge a b =
  Format.printf "\t%s -> %s\n" (Tid.to_string a) (Tid.to_string b)

let fork_path current_path current_node =
  let new_path = Array.append (Array.copy current_path.nodes) [|current_node|] in
  {start_node = current_path.start_node; nodes = new_path; end_node = current_path.end_node;}

let node_already_visited_on_path node path =
  node = path.start_node || Array.exists path.nodes ~f:(fun n -> n = node)

let rec get_all_paths_from_node node g current_path =
  match Seq.to_list (Graphs.Tid.Node.succs node g) with
  | [] -> [current_path]
  | succs -> List.concat_map succs
               ~f:(fun succ ->
                   if node_already_visited_on_path succ current_path then
                     []
                   else
                     get_all_paths_from_node succ g (fork_path current_path node))

(* Please mind the path explosion !!! *)
let enumerate_paths_between_blks sub blk_start_tid blk_end_tid limit =
  let g = Sub.to_graph sub in
  let pathes = get_all_paths_from_node blk_start_tid g {start_node = blk_start_tid; nodes = [||]; end_node = blk_end_tid} in
  Format.printf "\tFound %d pathes.\n" (List.length pathes); []
