open Core_kernel.Std
open Bap.Std
open Symbol_utils    

include Self()

let name  = "CWE243"
let version = "0.1"

let get_call_dests_of_blk blk_tid sub =
  match Term.find blk_t sub blk_tid with
  | Some blk -> begin
      Term.enum jmp_t blk
    |> Seq.filter_map ~f:(fun jmp -> match Jmp.kind jmp with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call destination -> begin
              match Call.target destination with
              | Direct addr -> Some addr
              | _ -> None
            end)
     end |> Seq.to_list
  | _ -> []

let get_call_dests_of_sub sub =
  let entry_blk =(Term.first blk_t sub) in
  match entry_blk with
  | Some blk -> begin
    let blks = Graphlib.Std.Graphlib.postorder_traverse (module Graphs.Tid) (Sub.to_graph sub) ~start:(Term.tid blk) ~rev:true in
    List.concat_map (Seq.to_list blks) ~f:(fun blk -> get_call_dests_of_blk blk sub)
    end
  | _ -> []

let rec check dests symbols = 
  match dests with
  | [] -> (List.length symbols) = 0
  | hd :: tl -> 
    begin
    match symbols with
      | [] -> true
      | first_symbol :: symbol_rest -> begin
          match first_symbol.address with
          | Some address -> if address = hd then check tl symbol_rest else check tl symbols
          | _ -> false
        end
  end

let check_route sub symbols =
  let call_dests = get_call_dests_of_sub sub in 
  let res = check call_dests symbols in
  if res then res else res

(** Checks one possible valid path (combination of APIs) of chroot. *)
let check_path prog tid_map sub path =
  let symbols = build_symbols path prog in
  if List.length symbols = List.length path then
  begin
  if List.length symbols = List.length path then
      check_route sub symbols
  else
      false
  end
  else
    false

(** Checks a subfunction for CWE-243. Only functions that actually call "chroot" are considered. 
It checks each of the configured VALID pathes found in config.json, e.g.
 "chroot_pathes": [["chroot", "chdir"], ["chdir", "chroot", "setresuid"], ["chdir", "chroot", "seteuid"],
 ["chdir", "chroot", "setreuid"], ["chdir", "chroot", "setuid"]].
If all of them fail then we supose that the program handles chroot on
*)
let check_subfunction prog tid_map sub pathes =
  if sub_calls_symbol prog sub "chroot" then
    begin
      let path_checks = List.map pathes ~f:(fun path -> check_path prog tid_map sub path) in
      if not (List.exists path_checks ~f:(fun x -> x = true)) then
       Log_utils.warn
         "[%s] {%s} (The program utilizes chroot without dropping privileges and/or changing the directory) at %s (%s)"
         name
         version
         (Address_translation.translate_tid_to_assembler_address_string (Term.tid sub) tid_map)
         (Term.name sub)
    end

let check_cwe prog proj tid_map pathes =
  let chroot_symbol = find_symbol prog "chroot" in
  match chroot_symbol with
  | Some _ ->
    Seq.iter (Term.enum sub_t prog) ~f:(fun sub -> check_subfunction prog tid_map sub pathes)
  | _ -> ()
