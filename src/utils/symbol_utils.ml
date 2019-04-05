open Core_kernel
open Bap.Std

type symbol =
  {
    address : tid option;
    name : string;
  }


let find_symbol program name =
  Term.enum sub_t program |>
    Seq.find_map ~f:(fun s -> Option.some_if (Sub.name s = name) (Term.tid s))

let build_symbols symbol_names prog =
  List.map symbol_names ~f:(fun symbol -> let symbol_address = find_symbol prog symbol in
                             {address = symbol_address; name = symbol;})
  |> List.filter ~f:(fun symbol -> match symbol.address with
      | Some _ -> true
      | _ -> false)

let get_symbol_of_string prog name =
  let symbol_address = find_symbol prog name in
  match symbol_address with
  | Some address -> Some ({
                          address = symbol_address
                          ; name = name
                          })
  | None -> None

let get_symbol tid symbols =
  List.find symbols ~f:(
    fun symbol -> match symbol.address with
      | Some address -> tid = address
      | None -> false)

let get_symbol_name_from_jmp jmp symbols =
    match Jmp.kind jmp with
    | Goto _ | Ret _ | Int (_,_) -> assert(false)
    | Call destination -> begin
        match Call.target destination with
        | Direct addr ->
          begin
            let symbol = List.find symbols ~f:(fun symbol -> match symbol.address with
                | Some address -> addr = address
                | _ -> assert(false)) in match symbol with
            | Some s -> s.name
            | _ -> assert(false)
          end
        | _ -> assert(false)
      end

let get_direct_callsites_of_sub sub =
Term.enum blk_t sub |>
  Seq.concat_map ~f:(fun blk ->
      Term.enum jmp_t blk |> Seq.filter_map ~f:(fun j ->
          match Jmp.kind j with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call destination -> begin match Call.target destination with
            | Direct tid -> Some j
            | _ -> None
            end))

let sub_calls_symbol prog sub symbol_name =
  let symbol_struct = find_symbol prog symbol_name in
  match symbol_struct with
  | Some s -> begin
    let callsites = get_direct_callsites_of_sub sub in
    Seq.exists callsites ~f:(fun callsite -> match Jmp.kind callsite with
            | Goto _ | Ret _ | Int (_,_) -> false
            | Call destination -> match Call.target destination with
              | Direct addr -> addr = s
              | _ -> false)
  end
  | _ -> false

let calls_callsite_symbol jmp symbol =
  match Jmp.kind jmp with
  | Goto _ | Ret _ | Int (_,_) -> false
  | Call dst -> match Call.target dst with
    | Direct tid -> match symbol.address with
      | Some symbol_tid -> tid = symbol_tid
      | None -> false
  | _ -> false


type concrete_call =
  {
    call_site : tid;
    symbol_address : tid;
    name : string;
  }

let call_finder = object
  inherit [(tid * tid) list] Term.visitor
  method! enter_jmp jmp tid_list = match Jmp.kind jmp with
    | Goto _ | Ret _ | Int (_,_) -> tid_list
    | Call destination -> begin
        match Call.target destination with
        | Direct addr -> (Term.tid jmp, addr) :: tid_list
        | _ -> tid_list
      end
end


let transform_call_to_concrete_call (src_tid, dst_tid) symbols =
  match (get_symbol dst_tid symbols) with
  | Some symbol -> {call_site = src_tid; symbol_address = dst_tid; name = symbol.name}
  | None -> assert(false)

let filter_calls_to_symbols calls symbols =
  List.filter calls ~f:(
    fun (_, dst) -> List.exists symbols ~f:(
        fun symbol -> match symbol.address with
          | Some address -> address = dst
          | None -> false))
|> List.map ~f:(fun call -> transform_call_to_concrete_call call symbols)

let is_interesting_callsite jmp relevant_calls =
  match Jmp.kind jmp with
          | Goto _ | Ret _ | Int (_,_) -> false
          | Call dst -> match Call.target dst with
            | Direct tid -> List.exists relevant_calls ~f:(fun c -> c.symbol_address = tid)
            | _ -> false


let check_calls relevant_calls prog proj tid_map symbols check_func =
  Seq.iter (Term.enum sub_t prog)
    ~f:(fun sub ->
        begin
          Seq.iter (Term.enum blk_t sub)
           ~f:(fun blk -> Seq.iter (Term.enum jmp_t blk)
                  ~f:(fun jmp -> if is_interesting_callsite jmp relevant_calls then
                     check_func proj prog sub blk jmp tid_map symbols))
        end)

let get_symbol_call_count_of_sub symbol_name sub prog =
  match find_symbol prog symbol_name with
  | Some s -> begin
                Seq.to_list (get_direct_callsites_of_sub sub)
                |> List.filter ~f:(fun callsite ->
                    match Jmp.kind callsite with
                    | Goto _ | Ret _ | Int (_,_) -> false
                    | Call destination -> match Call.target destination with
                      | Direct addr -> addr = s
                      | _ -> false)
                |> List.length
              end
  | _ -> 0

let extract_direct_call_tid_from_block block =
  let jmp_instructions = Term.enum jmp_t block in
  Seq.fold jmp_instructions ~init:None ~f:(fun already_found instr ->
    match already_found with
      | Some(symb) -> Some(symb)
      | None ->
        match Jmp.kind instr with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call dst -> match Call.target dst with
            | Direct tid ->
              Some(tid)
            | _ -> None)

let get_program_entry_points program =
  let subfunctions = Term.enum sub_t program in
  let entry_points = Seq.filter subfunctions ~f:(fun subfn -> Term.has_attr subfn Sub.entry_point) in
  let main_fn = Seq.filter subfunctions ~f:(fun subfn -> "@main" = Tid.name (Term.tid subfn)) in
  Seq.append main_fn entry_points

let stack_register project =
  let arch = Project.arch project in
  let module Target = (val target_of_arch arch) in
  Target.CPU.sp

let flag_register_list project =
  let arch = Project.arch project in
  let module Target = (val target_of_arch arch) in
  Target.CPU.zf :: Target.CPU.cf :: Target.CPU.vf :: Target.CPU.nf :: []

let arch_pointer_size_in_bytes project : int =
  let arch = Project.arch project in
  Size.in_bytes (Arch.addr_size arch)
