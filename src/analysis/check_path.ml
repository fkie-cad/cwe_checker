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

let find_sub prog name =
  Term.enum sub_t prog |>
  Seq.find_map ~f:(fun s ->
      Option.some_if (Sub.name s = name) (Term.tid s))

let reaches cg callee target =
  Graphlib.is_reachable (module CG) cg callee target

let callsites cg target sub =
  Term.enum blk_t sub |>
  Seq.concat_map ~f:(fun blk ->
      Term.enum jmp_t blk |> Seq.filter_map ~f:(fun j ->
          match Jmp.kind j with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call dst -> match Call.target dst with
            | Direct tid when reaches cg tid target ->
              Some (Term.tid blk)
            | _ -> None))

let _verify src dst prog : proof option =
  let cg = Program.to_graph prog in
  match Graphlib.shortest_path (module CG) cg src dst with
  | Some path -> Some (Calls path)
  | None ->
    Term.enum sub_t prog |> Seq.find_map ~f:(fun sub ->
        let g = Sub.to_graph sub in
        Seq.find_map (callsites cg src sub) ~f:(fun sc ->
            Seq.find_map (callsites cg dst sub) ~f:(fun dc ->
                if Tid.equal sc dc then None
                else Graphlib.shortest_path (module CFG) g sc dc))) |>
    Option.map ~f:(fun p -> Sites p)

let check_path prog _proj _tid_map input_functions _cwe_hits =
  List.iter input_functions ~f:(fun f ->
      match find_sub prog f with
      | Some _sym -> printf "Not yet implemented."
      | None -> printf "Symbol %s not found in binary." f)
