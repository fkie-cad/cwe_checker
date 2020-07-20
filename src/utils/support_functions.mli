(** Calls objdump with customisable flag and error message. Returns output lines as string list. *)
val call_objdump : Bap.Std.Project.t -> flag:string -> err:string -> string list
