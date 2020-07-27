open Core_kernel
open Bap.Std

type symbol =
  {
    address : tid option;
    name : string;
  }


type extern_symbol =
  {
    tid : tid;
    address : string;
    name : string;
    cconv : string option;
    args : (Var.t * Exp.t * intent option) list;
  }


let extern_symbol_blacklist = [
  "__cxa_atexit";
  "__libc_start_main";
  "__cxa_finalize"
]


let extern_symbols = ref []

let dyn_syms = ref None

let found_calls = ref []

let call_finder_run = ref false


(** Parse a line from the dyn-syms output table of objdump. Return the name of a symbol if the symbol is an extern function name. *)
let parse_dyn_sym_line (line : string) : string option =
  let line = ref (String.strip line) in
  let str_list = ref [] in
  while Option.is_some (String.rsplit2 !line ~on:' ') do
    let (left, right) = Option.value_exn (String.rsplit2 !line ~on:' ') in
    line := String.strip left;
    str_list := right :: !str_list;
  done;
  str_list := !line :: !str_list;
  match !str_list with
  | value :: func1 :: func2 :: _ -> begin
      match ( String.strip ~drop:(fun x -> x = '0') value ) with
      | "" -> begin
          if (String.equal func1 "DF" || String.equal func2 "DF") then (
            List.last !str_list
          )
          else None
        end
      | _ -> None (* The symbol has a nonzero value, so we assume that it is not an extern function symbol. *)
    end
  | _ -> None


let parse_dyn_syms (project : Project.t) : String.Set.t =
  match !dyn_syms with
  | Some(symbol_set) -> symbol_set
  | None -> begin
      let lines = Support_functions.call_objdump project ~flag:"--dynamic-syms" ~err:"[cwe_checker] Parsing of dynamic symbols failed:" in
      match lines with
      | _ :: _ :: _ :: _ :: tail -> (* The first four lines are not part of the table *)
          let symbol_set = String.Set.of_list (List.filter_map tail ~f:parse_dyn_sym_line) in
          dyn_syms := Some(symbol_set);
          symbol_set
      | _ ->
          dyn_syms := Some(String.Set.empty);
          String.Set.empty
    end


let get_project_calling_convention (project : Project.t) : string option =
  Project.get project Bap_abi.name


let build_extern_symbols (project : Project.t) (program : program term) (parsed_symbols : string list) (tid_map : word Tid.Map.t) : unit =
  let calling_convention = get_project_calling_convention project in
  extern_symbols := List.append !extern_symbols (Seq.to_list (Seq.filter_map (Term.enum sub_t program) ~f:(fun s ->
    let sub_name = Sub.name s in
    let sub_tid = Term.tid s in
    match (Stdlib.List.mem sub_name parsed_symbols) with
    | true -> begin
        let addr = Address_translation.translate_tid_to_assembler_address_string sub_tid tid_map in
        let args = Seq.to_list (Seq.map (Term.enum arg_t s) ~f:(fun a -> (Arg.lhs a, Arg.rhs a, Arg.intent a))) in
        Some({tid=sub_tid; address=addr; name=sub_name; cconv=calling_convention; args=args;})
      end
    | false -> None)))


let build_and_return_extern_symbols (project : Project.t) (program : program term) (tid_map : word Tid.Map.t) : extern_symbol list =
  let parsed_symbols = parse_dyn_syms project in
  if String.Set.is_empty parsed_symbols then []
  else begin
    match !extern_symbols with
    | [] -> build_extern_symbols project program (String.Set.to_list parsed_symbols) tid_map; !extern_symbols
    | _  -> !extern_symbols
  end


let add_as_extern_symbol (project : Project.t) (program : program term) (symbol : string) (tid_map : word Tid.Map.t) : unit =
  Seq.iter (Term.enum sub_t program) ~f:(fun s ->
    match String.equal (Sub.name s) symbol with
    | true -> begin
        let sub_tid = Term.tid s in
        let args = Seq.to_list (Seq.map (Term.enum arg_t s) ~f:(fun a -> (Arg.lhs a, Arg.rhs a, Arg.intent a))) in
        let addr = Address_translation.translate_tid_to_assembler_address_string sub_tid tid_map in
        extern_symbols := List.append !extern_symbols [{tid=sub_tid; address=addr; name=(Sub.name s); cconv=(get_project_calling_convention project); args=args}]
      end
    | false -> ()
  )


let find_symbol (program : program term) (name : string) : tid option =
  Term.enum sub_t program |>
  Seq.find_map ~f:(fun s -> Option.some_if (Sub.name s = name) (Term.tid s))


let build_symbols (symbol_names : string list) (prog : program term) : symbol list =
  List.map symbol_names ~f:(fun symbol -> let symbol_address = find_symbol prog symbol in
                             {address = symbol_address; name = symbol;})
  |> List.filter ~f:(fun symbol -> match symbol.address with
      | Some _ -> true
      | _ -> false)


let get_symbol_of_string (prog : program term) (name : string) : symbol option =
  let symbol_address = find_symbol prog name in
  match symbol_address with
  | Some _ -> Some ({
                          address = symbol_address
                          ; name = name
                          })
  | None -> None


let get_symbol (tid : tid) (symbols : symbol list) : symbol option =
  List.find symbols ~f:(
    fun symbol -> match symbol.address with
      | Some address -> tid = address
      | None -> false)


let get_symbol_name_from_jmp (jmp : Jmp.t) (symbols : symbol list) : string =
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


let get_direct_callsites_of_sub (sub : sub term) : jmp term Sequence.t =
Term.enum blk_t sub |>
  Seq.concat_map ~f:(fun blk ->
      Term.enum jmp_t blk |> Seq.filter_map ~f:(fun j ->
          match Jmp.kind j with
          | Goto _ | Ret _ | Int (_,_) -> None
          | Call destination -> begin match Call.target destination with
            | Direct _tid -> Some j
            | _ -> None
            end))


let sub_calls_symbol (prog : program term) (sub : sub term) (symbol_name : string) : bool =
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


let calls_callsite_symbol (jmp : Jmp.t) (symbol : symbol) : bool =
  match Jmp.kind jmp with
  | Goto _ | Ret _ | Int (_,_) -> false
  | Call dst -> begin
      match Call.target dst with
      | Direct tid -> begin
            match symbol.address with
            | Some symbol_tid -> tid = symbol_tid
            | None -> false
          end
      | _ -> false
    end


type concrete_call =
  {
    call_site : tid;
    symbol_address : tid;
    name : string;
  }


let call_finder : (tid * tid) list Term.visitor = object
  inherit [(tid * tid) list] Term.visitor
  method! enter_jmp jmp tid_list = match Jmp.kind jmp with
    | Goto _ | Ret _ | Int (_,_) -> tid_list
    | Call destination -> begin
        match Call.target destination with
        | Direct addr -> (Term.tid jmp, addr) :: tid_list
        | _ -> tid_list
      end
end


let get_calls (program : program term) : (tid * tid) list =
  match !call_finder_run with
  | true -> !found_calls
  | false -> begin
      call_finder_run := true;
      found_calls := call_finder#run program [];
      !found_calls
  end


let check_if_symbols_resolved (project : Project.t) (program : program term) (tid_map : word Tid.Map.t) : bool =
  let extern = build_and_return_extern_symbols project program tid_map in
  let extern = List.filter extern ~f:(fun ext_sym -> not (Stdlib.List.mem ext_sym.name extern_symbol_blacklist)) in
  match List.is_empty extern with
  | true -> false
  | false -> begin
      let calls = List.map (get_calls program) ~f:(fun call -> match call with (_, dst) -> dst) in
      let not_resolved = List.filter extern ~f:(fun ext_sym -> not (Stdlib.List.mem ext_sym.tid calls)) in
      not (List.length extern = List.length not_resolved)
  end



let transform_call_to_concrete_call ((src_tid, dst_tid) : tid * tid) (symbols : symbol list) : concrete_call =
  match (get_symbol dst_tid symbols) with
  | Some symbol -> {call_site = src_tid; symbol_address = dst_tid; name = symbol.name}
  | None -> assert(false)


let filter_calls_to_symbols (calls : (tid * tid) list) (symbols : symbol list) : concrete_call list =
  List.filter calls ~f:(
    fun (_, dst) -> List.exists symbols ~f:(
        fun symbol -> match symbol.address with
          | Some address -> address = dst
          | None -> false))
|> List.map ~f:(fun call -> transform_call_to_concrete_call call symbols)


let is_interesting_callsite (jmp : Jmp.t) (relevant_calls : concrete_call list): bool =
  match Jmp.kind jmp with
          | Goto _ | Ret _ | Int (_,_) -> false
          | Call dst -> match Call.target dst with
            | Direct tid -> List.exists relevant_calls ~f:(fun c -> c.symbol_address = tid)
            | _ -> false


let check_calls (relevant_calls : concrete_call list) (prog : program term) (proj : 'a) (tid_map : 'b) (symbols : 'c) (check_func) : unit =
  Seq.iter (Term.enum sub_t prog)
    ~f:(fun sub ->
        begin
          Seq.iter (Term.enum blk_t sub)
           ~f:(fun blk -> Seq.iter (Term.enum jmp_t blk)
                  ~f:(fun jmp -> if is_interesting_callsite jmp relevant_calls then
                     check_func proj prog sub blk jmp tid_map symbols))
        end)


let get_symbol_call_count_of_sub (symbol_name : string) (sub : Sub.t) (prog : Program.t) : int =
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


let extract_direct_call_tid_from_block (block : blk term) : tid option =
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


let get_program_entry_points (program : program term) : sub term List.t =
  let subfunctions = Term.enum sub_t program in
  let entry_points = Seq.filter subfunctions ~f:(fun subfn -> Term.has_attr subfn Sub.entry_point) in
  match Seq.find subfunctions ~f:(fun subfn -> "main" = Sub.name subfn) with
  | Some(main_fn) ->
      if Seq.exists entry_points ~f:(fun elem -> elem = main_fn) then
        Seq.to_list entry_points
      else
        main_fn :: (Seq.to_list entry_points)
  | None -> Seq.to_list entry_points


let stack_register (project : Project.t) : Var.t =
  let arch = Project.arch project in
  let module Target = (val target_of_arch arch) in
  Target.CPU.sp


let flag_register_list (project : Project.t) : Var.t list =
  let arch = Project.arch project in
  let module Target = (val target_of_arch arch) in
  Target.CPU.zf :: Target.CPU.cf :: Target.CPU.vf :: Target.CPU.nf :: []


let arch_pointer_size_in_bytes (project : Project.t) : int =
  let arch = Project.arch project in
  Size.in_bytes (Arch.addr_size arch)
