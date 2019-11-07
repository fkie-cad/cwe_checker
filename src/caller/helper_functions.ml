open Core_kernel


(* Removes the nth element of a list *)
let rec remove_nth (in_list : 'a list) (n : int) : 'a list =
  match in_list with
  | []         -> []
  | head::tail -> if n = 0 then tail else head::remove_nth tail (n-1)


(* Removes element from list based on prefix *)
let rec remove_element (set: string list) (prefix : string) : string list =
  match set with
  | [] -> []
  | head::tail ->
    match String.is_prefix ~prefix:prefix head with
    | true -> remove_element tail prefix
    | false -> remove_element (head::tail) prefix


(* Replaces an element in a list if present, with a replacement value *)
let rec replace_element (set : string list) (element : string) (replacement : string) : string list =
  match set with
  | []         -> []
  | head::tail ->
    match String.is_prefix ~prefix:element head with
    | true  -> replacement::tail
    | false -> head::replace_element tail element replacement


(* Just for type conversion: Returns an empty string if none, else the string *)
let get_default_string (in_option : string option) : string =
  match in_option with
  | None   -> ""
  | Some s -> s


(* Returns all elements only present in set_a *)
let rec get_difference (set_a : 'a list) (set_b: 'a list) : 'a list =
  match set_a with
  | [] -> []
  | element_of_a::remain_a ->
    match (Stdlib.List.mem element_of_a set_b) with
    | true  -> get_difference remain_a set_b
    | false -> List.append (get_difference remain_a set_b) [element_of_a]


(* Returns user input from the command line from given position as a string list *)
let get_user_input ?(position=1) (() : unit) : string list =
  Array.to_list (Array.sub Sys.argv ~pos:position ~len:(Array.length Sys.argv - position))


(* Returns flag with file attachment if present *)
let rec find_prefix (input : string list) (prefix : string) : string option =
  match input with
  | []         -> None
  | head::tail ->
    match (String.is_prefix head ~prefix:prefix) with
    | true  -> Some head
    | false -> find_prefix tail prefix
