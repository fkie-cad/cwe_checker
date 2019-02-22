open Core_kernel.Std
open Bap.Std

let name = "CWE457"
let version = "0.1"

let get_defs sub_ssa =
  Term.enum blk_t sub_ssa
  |> Seq.concat_map ~f:(fun blk -> Term.enum def_t blk)

let collect_stores_of_exp = Exp.fold ~init:0 (object
          inherit [int] Exp.visitor
          method! enter_store ~mem:_ ~addr:addr ~exp:exp _ _ stores =
            stores + 1
        end)

let exp_has_store e =
  collect_stores_of_exp e > 0

let ints_of_exp = Exp.fold ~init:Word.Set.empty (object
          inherit [Word.Set.t] Exp.visitor
          method! enter_int i ints = Set.add ints i
        end)

let vars_of_exp = Exp.fold ~init:Var.Set.empty (object
    inherit [Var.Set.t] Exp.visitor
    method! enter_var var vars = Set.add vars var
end)

let vars_contain_mem vars =
  let mems = Set.filter vars ~f:(fun var -> match Var.to_string var with
                                            | "mem" -> true
                                            | _ -> false) in
  Set.length mems > 0

(*FIXME: this is architecture dependent and ugly*)
let get_min_fp_offset arch =
  match arch with
  | `x86 | `x86_64 -> 0x10000
  | _ -> 0x0

(*FIXME: this is architecture dependent and ugly*)
let get_fp_of_arch arch =
  match arch with
  | `x86 -> "EBP"
  | `x86_64 -> "RBP"
  | `armv4 | `armv5 | `armv6 | `armv7 | `armv4eb | `armv5eb | `armv6eb | `armv7eb -> "R11"
  | `mips | `mips64 | `mips64el | `mipsel -> "FP"
  | `ppc | `ppc64 | `ppc64le -> "R31"
  | _ -> Log_utils.error "[%s] {%s} Unknown architecture." name version; "UNKNOWN"

let vars_contain_fp vars fp_pointer =
  let regs = Set.filter vars ~f:(fun var -> Var.to_string var = fp_pointer) in
  Set.length regs > 0

let is_interesting_load_store def fp_pointer =
  let vars = vars_of_exp (Def.rhs def) in
  let contains_fp = vars_contain_fp vars fp_pointer in
  let contains_mem = vars_contain_mem vars in
  contains_mem && contains_fp

(*TODO: implement real filtering*)
let filter_mem_address i min_fp_offset = Set.filter i ~f:(fun elem -> (Word.of_int  ~width:32 min_fp_offset) < elem)

let check_subfunction prog proj tid_map sub =
  let fp_pointer = get_fp_of_arch (Project.arch proj) in
  let min_fp_offset = get_min_fp_offset (Project.arch proj) in
  let stores = ref [||] in
  let defs = get_defs sub in
  Seq.iter defs ~f:(fun d ->
      if is_interesting_load_store d fp_pointer then
        let rhs = Def.rhs d in
        let ints = ints_of_exp rhs in
        begin
          if exp_has_store rhs then
            begin
              let filter_mem_addresses = filter_mem_address ints min_fp_offset in
              Set.iter filter_mem_addresses ~f:(fun addr -> stores := Array.append !stores [|addr|])
            end
          else
            begin
              let filter_mem_addresses = filter_mem_address ints min_fp_offset in
              Set.iter filter_mem_addresses ~f:(fun i -> if not (Array.exists !stores ~f:(fun elem -> elem = i)) then
                                           begin
                                           Log_utils.warn "[%s] {%s} (Use of Uninitialized Variable) Found potentially unitialized stack variable (FP + %s) in function %s at %s"
                                             name
                                             version
                                             (Word.to_string i)
                                             (Sub.name sub)
                                             (Address_translation.translate_tid_to_assembler_address_string (Term.tid d) tid_map)
                                           end)
            end
        end)

let check_cwe prog proj tid_map symbol_names _ =
  Seq.iter (Term.enum sub_t prog) ~f:(fun sub -> check_subfunction prog proj tid_map sub)
