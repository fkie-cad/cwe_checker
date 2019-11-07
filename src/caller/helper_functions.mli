(* Removes the nth element of a list *)
val remove_nth: 'a list -> int -> 'a list

(* Removes element from list based on prefix *)
val remove_element: string list -> string -> string list

(* Replaces an element in a list if present, with a replacement value *)
val replace_element: string list -> string -> string -> string list

(* Just for type conversion: Returns an empty string if none, else the string *)
val get_default_string: string option -> string

(* Returns all elements only present in set_a *)
val get_difference: 'a list -> 'a list -> 'a list

(* Returns user input from the command line from given position as a string list *)
val get_user_input: ?position:int -> unit -> string list

(* Returns flag with file attachment if present *)
val find_prefix: string list -> string -> string option
