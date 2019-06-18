open Bap.Std
open Core_kernel


let (+), (-) = Bitvector.(+), Bitvector.(-)

let (>) x y = Bitvector.(>) (Bitvector.signed x) (Bitvector.signed y)
let (<) x y = Bitvector.(<) (Bitvector.signed x) (Bitvector.signed y)
(* let (>=) x y = Bitvector.(>=) (Bitvector.signed x) (Bitvector.signed y) *)
let (<=) x y = Bitvector.(<=) (Bitvector.signed x) (Bitvector.signed y)
let (=) x y = Bitvector.(=) x y

type 'a mem_node = {
  pos: Bitvector.t; (* address of the element *)
  size: Bitvector.t; (* size (in bytes) of the element *)
  data: ('a, unit) Result.t;
} [@@deriving bin_io, compare, sexp]

type 'a t = 'a mem_node list [@@deriving bin_io, compare, sexp]


let empty () : 'a t =
  []

(** Return an error mem_node at the given position with the given size. *)
let error_elem ~pos ~size =
  { pos = pos;
    size = size;
    data = Error ();}


let rec add mem_region elem ~pos ~size =
  let () = if pos + size < pos then failwith "[CWE-checker] element out of bounds for mem_region" in
  let new_node = {
    pos=pos;
    size=size;
    data=Ok(elem);
  } in
  match mem_region with
  | [] -> new_node :: []
  | head :: tail ->
    if head.pos + head.size <= pos then
      head :: (add tail elem ~pos ~size)
    else if pos + size <= head.pos then
      new_node :: mem_region
    else begin (* head and new node intersect => at the intersection, head gets overwritten and the rest of head gets marked as error. *)
      let tail = if head.pos + head.size > pos + size then (* mark the right end of head as error *)
          let err = error_elem ~pos:(pos + size) ~size:(head.pos + head.size - (pos + size)) in
          err :: tail
        else
          tail in
      let tail = add tail elem ~pos ~size in (* add the new element*)
      let tail = if head.pos < pos then (* mark the left end of head as error *)
          let err = error_elem ~pos:(head.pos) ~size:(pos - head.pos) in
          err :: tail
        else
          tail in
      tail
    end


let rec get mem_region pos =
  match mem_region with
  | [] -> None
  | head :: tail ->
    if head.pos > pos then
      None
    else if head.pos = pos then
      match head.data with
      | Ok(x) -> Some(Ok(x, head.size))
      | Error(_) -> Some(Error(()))
    else if head.pos + head.size <= pos then
      get tail pos
    else
      Some(Error(())) (* pos intersects some data, but does not equal its starting address*)


let rec remove mem_region ~pos ~size =
  let () = if pos + size < pos then failwith "[CWE-checker] element out of bounds for mem_region" in
  match mem_region with
  | [] -> []
  | hd :: tl ->
    if hd.pos + hd.size <= pos then
      hd :: remove tl ~pos ~size
    else if pos + size <= hd.pos then
      mem_region
    else
      let mem_region = remove tl ~pos ~size in
      let mem_region =
        if hd.pos + hd.size > pos + size then
          error_elem ~pos:(pos + size) ~size:(hd.pos + hd.size - (pos + size)) :: mem_region
        else
          mem_region in
      let mem_region =
        if hd.pos < pos then
          error_elem ~pos:hd.pos ~size:(pos - hd.pos) :: mem_region
        else
          mem_region in
      mem_region

let rec mark_error mem_region ~pos ~size =
  let () = if pos + size < pos then failwith "[CWE-checker] element out of bounds for mem_region" in
  match mem_region with
  | [] -> (error_elem ~pos ~size) :: []
  | hd :: tl ->
    if hd.pos + hd.size <= pos then
      hd :: (mark_error tl ~pos ~size)
    else if pos + size <= hd.pos then
      (error_elem ~pos ~size) :: mem_region
    else
      let start_pos = min pos hd.pos in
      let end_pos_plus_one = max (pos + size) (hd.pos + hd.size) in
      mark_error tl ~pos:start_pos ~size:(end_pos_plus_one - start_pos)


(* TODO: This is probably a very inefficient implementation in some cases. Write a faster implementation if necessary. *)
let rec merge mem_region1 mem_region2 ~data_merge =
  match (mem_region1, mem_region2) with
  | (value, [])
  | ([], value) -> value
  | (hd1 :: tl1, hd2 :: tl2) ->
    if hd1.pos + hd1.size <= hd2.pos then
      hd1 :: merge tl1 mem_region2 ~data_merge
    else if hd2.pos + hd2.size <= hd1.pos then
      hd2 :: merge mem_region1 tl2 ~data_merge
    else if hd1.pos = hd2.pos && hd1.size = hd2.size then
      match (hd1.data, hd2.data) with
      | (Ok(data1), Ok(data2)) -> begin
          match data_merge data1 data2 with
          | Some(Ok(value)) -> { hd1 with data = Ok(value) } :: merge tl1 tl2 ~data_merge
          | Some(Error(_)) -> {hd1 with data = Error(())} :: merge tl1 tl2 ~data_merge
          | None -> merge tl1 tl2 ~data_merge
        end
      | _ -> { hd1 with data = Error(()) } :: merge tl1 tl2 ~data_merge
    else
      let start_pos = min hd1.pos hd2.pos in
      let end_pos_plus_one = max (hd1.pos + hd1.size) (hd2.pos + hd2.size) in
      let mem_region = merge tl1 tl2 ~data_merge in
      mark_error mem_region ~pos:start_pos ~size:(end_pos_plus_one - start_pos)


let rec equal (mem_region1:'a t) (mem_region2:'a t) ~data_equal : bool =
  match (mem_region1, mem_region2) with
  | ([], []) -> true
  | (hd1 :: tl1, hd2 :: tl2) ->
    if hd1.pos = hd2.pos && hd1.size = hd2.size then
      match (hd1.data, hd2.data) with
      | (Ok(data1), Ok(data2)) when data_equal data1 data2 ->
        equal tl1 tl2 ~data_equal
      | (Error(()), Error(())) -> equal tl1 tl2 ~data_equal
      | _ -> false
    else
      false
  | _ -> false
