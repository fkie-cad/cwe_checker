exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception InvalidModulesException of string
exception NoConfigException of string

(** A list of known CWE modules *)
val known_modules : string list

(** checks the validity of the -config flag *)
val config_check : string list -> bool

(** generates the output file path for the -out flag *)
val generate_output_file : string -> ?file:string -> unit -> string

(** builds a valid path for the output *)
val build_path : string -> string

(** processes ouput path. raises invalid path exception *)
val out_path : string -> string

(** raises an error if no path for output is given *)
val out_check : string -> string

(** sets the --cwe-checker prefix to all given flags *)
val setup_flags : string list -> string

(** checks if modules are given and if they are valid *)
val partial_check : string list -> bool

(** returns a list of valid flags from a json file *)
val get_from_json : string -> string list

(** checks if valid flags are given *)
val user_input_valid : string list -> bool

(** wrapper for entire flag processing *)
val process_flags : string list option
