open Core_kernel
open Yojson.Basic.Util
open Bap.Std
open Symbol_utils

(** Extracts the symbols to check for from json document.
An example looks like this:
"CWE467": {
	"symbols": ["strncmp", "malloc",
		    "alloca", "_alloca", "strncat", "wcsncat",
		    "strncpy", "wcsncpy", "stpncpy", "wcpncpy",
		    "memcpy", "wmemcpy", "memmove", "wmemmove", "memcmp", "wmemcmp"],
	"_comment": "any function that takes something of type size_t could be a possible candidate."
    }, *)
let get_symbols_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "symbols"
  |> flatten
  |> List.map ~f:to_string

let get_symbol_lists_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "pairs"
  |> flatten
  |> List.map ~f:(fun l -> List.map (to_list l) ~f:to_string)

let get_parameter_list_from_json json cwe =
  [json]
  |> filter_member cwe
  |> filter_member "parameters"
  |> flatten
  |> List.map ~f:to_string


module SerdeJson = struct

  type t = nativeint

  external rs_finalize_json_builder: t -> unit = "rs_finalize_json_builder"

  external rs_build_serde_null: unit -> t = "rs_build_serde_null"
  external rs_build_serde_bool: bool -> t = "rs_build_serde_bool"
  external rs_build_serde_number: int -> t = "rs_build_serde_number"
  external rs_build_serde_string: string -> t = "rs_build_serde_string"
  external rs_build_serde_array_from_list: t list -> t = "rs_build_serde_array_from_list"
  external rs_build_serde_object: (string * t) list -> t = "rs_build_serde_object"
  external rs_build_bitvector: string -> t = "rs_build_serde_bitvector"

  external rs_convert_json_to_string: t -> string = "rs_convert_json_to_string"

  let add_finalizer value =
    (Gc.Expert.add_finalizer_exn value rs_finalize_json_builder) (* TODO: if test throws Invalid_argument exceptions, the values to finalize must be wrapped in ref to ensure heap allocation! *)

  let build_null (): t =
    let value = rs_build_serde_null () in
    let () = add_finalizer value in
    value

  let build_number (num: int) : t =
    let value = rs_build_serde_number num in
    let () = add_finalizer value in
    value

  let build_bool (boolean: bool) : t =
    let value = rs_build_serde_bool boolean in
    let () = add_finalizer value in
    value

  let build_string (string_val: string) : t =
    let value = rs_build_serde_string string_val in
    let () = add_finalizer value in
    value

  let build_array (obj_list: t list) : t =
    let value = rs_build_serde_array_from_list obj_list in
    let () = add_finalizer value in
    value

  let build_object (entries: (string * t) list) : t =
    let value = rs_build_serde_object entries in
    let () = add_finalizer value in
    value

  let to_string (serde_json: t) : String.t =
    rs_convert_json_to_string serde_json

  let of_var_type (var_type: Bil.Types.typ) : t =
    match var_type with
    | Imm bitsize ->
        build_object (
          ("Immediate", build_number bitsize) :: []
        )
    | Mem (addr_size, size) ->
        build_object (
          ("Memory", build_object (
             ("addr_size", build_number (Size.in_bits addr_size)) ::
             ("elem_size", build_number (Size.in_bits size)) :: []
           )) :: [])
    | Unk -> build_string "Unknown"

  let of_var (var: Var.t) : t =
    build_object [
      ("name", build_string (Var.name var));
      ("type_", of_var_type (Var.typ var));
      ("is_temp", build_bool (Var.is_virtual var));
    ]

  let of_cast_type (cast_type: Bil.Types.cast) : t =
    build_string (Sexp.to_string (Bil.Types.sexp_of_cast cast_type))

  let of_binop_type (binop: Bil.Types.binop) : t =
    build_string (Sexp.to_string (Bil.Types.sexp_of_binop binop))

  let of_unop_type (unop: Bil.Types.unop) : t =
    build_string (Sexp.to_string (Bil.Types.sexp_of_unop unop))

  let of_endianness (endianness: Bitvector.endian) : t =
    build_string (Sexp.to_string (Bitvector.sexp_of_endian endianness))

  let of_bitvector (bitv: Bitvector.t) : t =
    let value = rs_build_bitvector (Bitvector.to_string bitv) in
    let () = add_finalizer value in
    value

  let rec of_exp (exp: Exp.t) : t =
    begin match exp with
    | Var(var) ->
        build_object (("Var", of_var var) :: [])
    | Int(bitvector) ->
        build_object (("Const", of_bitvector bitvector) :: [])
    | Load(mem, addr, endian, size) ->
        build_object [ ("Load", build_object [
          ("memory", of_exp mem);
          ("address", of_exp addr);
          ("endian", of_endianness endian);
          ("size", build_number (Size.in_bits size));
        ]);]
    | Store(mem, addr, value, endian, size) ->
        build_object [ ("Store", build_object [
          ("memory", of_exp mem);
          ("address", of_exp addr);
          ("value", of_exp value);
          ("endian", of_endianness endian);
          ("size", build_number (Size.in_bits size));
        ]);]
    | BinOp(type_, lhs, rhs) ->
        build_object [ ("BinOp", build_object [
          ("op", of_binop_type type_);
          ("lhs", of_exp lhs);
          ("rhs", of_exp rhs);
        ]);]
    | UnOp(type_, exp) ->
        build_object [ ("UnOp", build_object [
          ("op", of_unop_type type_);
          ("arg", of_exp exp);
        ]);]
    | Cast(cast, width, exp) ->
        build_object [ ("Cast", build_object [
          ("kind", of_cast_type cast);
          ("width", build_number width);
          ("arg", of_exp exp);
        ]);]
    | Let(var, bound_exp, body_exp) ->
        build_object [ ("Let", build_object [
          ("var", of_var var);
          ("bound_exp", of_exp bound_exp);
          ("body_exp", of_exp body_exp)
        ]);]
    | Unknown(text, typ) ->
        build_object [ ("Unknown", build_object [
          ("description", build_string text);
          ("type_", of_var_type typ);
        ]);]
    | Ite(if_, then_, else_) ->
        build_object [ ("Ite", build_object [
          ("condition", of_exp if_);
          ("true_exp", of_exp then_);
          ("false_exp", of_exp else_);
        ]);]
    | Extract(high, low, exp) ->
        build_object [ ("Extract", build_object [
          ("low_bit", build_number low);
          ("high_bit", build_number high);
          ("arg", of_exp exp)
        ]);]
    | Concat(left, right) ->
        build_object [ ("Concat", build_object [
          ("left", of_exp left);
          ("right", of_exp right)
        ]);]
    end

  let of_tid (tid: Tid.t) : t =
    build_string (Tid.name tid)

  let of_def (def: Def.t) : t =
    build_object [
      ("tid", of_tid (Term.tid def));
      ("term", build_object [
         ("lhs", of_var (Def.lhs def));
         ("rhs", of_exp (Def.rhs def));
       ]);
    ]

  let of_jmp_label (jmp_label: label) : t =
    match jmp_label with
    | Direct(tid) ->
        build_object [
          ("Direct", of_tid tid);
        ]
    | Indirect(exp) ->
        build_object [
          ("Indirect", of_exp exp);
        ]

  let of_call (call: Call.t) : t =
    build_object [
      ("target", of_jmp_label (Call.target call));
      ("return_", match Call.return call with
       | Some(target) -> of_jmp_label target
       | None -> build_null ()
      );
    ]

  let of_jmp_kind (kind: jmp_kind) : t =
    match kind with
    | Call(call) ->
        build_object [
          ("Call", of_call call);
        ]
    | Goto(label) ->
        build_object [
          ("Goto", of_jmp_label label);
        ]
    | Ret(label) ->
        build_object [
          ("Return", of_jmp_label label);
        ]
    | Int(interrupt_num, tid) ->
        build_object [
          ("Interrupt", build_object [
             ("value", build_number interrupt_num );
             ("return_addr", of_tid tid)
           ]);
        ]

  let of_jmp (jmp: Jmp.t) : t =
    build_object [
      ("tid", of_tid (Term.tid jmp));
      ("term", build_object [
         ("condition", if Option.is_some (Jmp.guard jmp) then of_exp (Jmp.cond jmp) else build_null ());
         ("kind", of_jmp_kind (Jmp.kind jmp));
       ]);
    ]

  let of_blk (blk: Blk.t) : t =
    let defs = Seq.to_list (Term.enum def_t blk) in
    let defs = List.map defs ~f:(fun def -> of_def def) in
    let jmps = Seq.to_list (Term.enum jmp_t blk) in
    let jmps = List.map jmps ~f:(fun jmp -> of_jmp jmp) in
    build_object [
      ("tid", of_tid (Term.tid blk));
      ("term", build_object [
         ("defs", build_array defs);
         ("jmps", build_array jmps);
       ]);
    ]

  let of_sub (sub: Sub.t) : t =
    let blocks = Seq.to_list (Term.enum blk_t sub) in
    let blocks = List.map blocks ~f:(fun block -> of_blk block) in
    build_object [
      ("tid", of_tid (Term.tid sub));
      ("term", build_object [
         ("name", build_string (Sub.name sub));
         ("blocks", build_array blocks);
       ]);
    ]

  let of_extern_symbol (symbol: extern_symbol) : t =
    build_object [
      ("tid", of_tid symbol.tid);
      ("address", build_string symbol.address);
      ("name", build_string symbol.name);
      ("calling_convention", match symbol.cconv with
       | Some(cconv) -> build_string cconv
       | None -> build_null ()
       );
      ("arguments", build_array (List.map symbol.args ~f:(fun (var, expr, intent) ->
         build_object [
           ("var", of_var var);
           ("location", of_exp expr);
           ("intent", match intent with
            | Some(In) -> build_string "Input"
            | Some(Out) -> build_string "Output"
            | Some(Both) -> build_string "Both"
            | None -> build_string "Unknown"
           )
         ]
       )))
    ]

  let of_program (program: Program.t) (extern_symbols: extern_symbol List.t) : t =
    let subs = Seq.to_list (Term.enum sub_t program) in
    let subs = List.map subs ~f:(fun sub -> of_sub sub) in
    build_object [
      ("tid", of_tid (Term.tid program));
      ("term", build_object [
         ("subs", build_array subs);
         ("extern_symbols", build_array (List.map extern_symbols ~f:(fun sym -> of_extern_symbol sym)));
       ]);
    ]

  let of_project (project: Project.t) (extern_symbols: extern_symbol List.t) : t =
    build_object [
      ("program", of_program (Project.program project) extern_symbols);
      ("cpu_architecture", build_string (Arch.to_string (Project.arch project)));
      ("stack_pointer_register", of_var (Symbol_utils.stack_register project));
      ("callee_saved_registers", build_array (List.map (Cconv.callee_saved_register_list project) ~f:(fun reg_name -> build_string reg_name) ));
      ("parameter_registers", build_array (List.map (Cconv.get_parameter_register_list project) ~f:(fun reg_name -> build_string reg_name) ))
    ]

end
