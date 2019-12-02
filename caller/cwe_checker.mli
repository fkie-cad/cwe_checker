exception InvalidPathException of string
exception NoOutputFileException of string
exception NoModulesException of string
exception InvalidModulesException of string
exception NoConfigException of string
exception InvalidFlagException of string
exception NoArgumentsException of string
exception NoBinaryPathException of string

(** gets first element of tuple *)
val get_first : ('a * 'a) -> 'a

(** gets second element of tuple *)
val get_second : ('a * 'b) -> 'b

(** A list of known CWE modules *)
val get_known_modules : string list

(** get the difference between two sets A and B *)
val get_difference : 'a list -> 'a list -> 'a list

(** get user's input: default starts at index 1 *)
val get_user_input : ?position:int -> unit -> string list

(** iterate over a string list and get the element with a prefix match *)
val find_prefix : string list -> string -> string option

(** replace an element in a string list with a prefix match *)
val replace_element : string list -> string -> string -> string list

(** remove element from list with a prefix match *)
val remove_element : string list -> string -> string list

(** checks the validity of the -config flag *)
val check_config : string list -> unit

(** generates the output file path for the -out flag *)
val generate_output_file : string -> ?file:string -> unit -> string

(** builds a valid path for the output *)
val build_path : string -> string

(** extracts the output file path from the param and throws an exception if no path was given *)
val extract_output_path : string -> string

(** extracts the path from the set parameter and throws execption if invalid path is given *)
val output_check : string -> string

(** sets the --cwe-checker prefix to all given flags *)
val setup_flags : string list -> string

(** checks if modules are given and if they are valid *)
val check_partial : string list -> unit

(** checks if valid flags are given *)
val validate_user_input : string list -> unit

(** prints the help message *)
val help : unit -> unit

(** calls the help function and removes the help flag from the input if help flag is set *)
val check_for_help : string list -> bool

(** process flags put by user *)
val process_flags : string list -> string list

(** process params put by user *)
val process_params : string list -> string list

(** check wether a binary path was provided *)
val check_for_binary_path : string list -> string

(** wrapper for entire flag processing *)
val process_input : string * string list
