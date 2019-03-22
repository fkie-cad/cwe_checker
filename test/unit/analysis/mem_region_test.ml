open Bap.Std
open Core_kernel.Std

let check msg x = Alcotest.(check bool) msg true x

let test_add () : unit =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "Five" ~pos:(bv 3) ~size:(bv 5) in
  let x = Mem_region.add x "Seven" ~pos:(bv 9) ~size:(bv 7) in
  let x = Mem_region.add x "Three" ~pos:(bv 0) ~size:(bv 3) in
  check "add_ok" (Some(Ok("Five")) = (Mem_region.get x (bv 3)));
  check "add_err" (Some(Error(())) = (Mem_region.get x (bv 1)));
  check "add_none" (None = (Mem_region.get x (bv 8)))

let test_minus () =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "One" ~pos:(bv (-8)) ~size:(bv 8) in
  check "negative_index" (Some(Ok("One")) = Mem_region.get x (Bitvector.unsigned (bv (-8))))

let test_remove () =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "One" ~pos:(bv 0) ~size:(bv 10) in
  let x = Mem_region.add x "Two" ~pos:(bv 15) ~size:(bv 11) in
  let x = Mem_region.remove x ~pos:(bv 5) ~size:(bv 20) in
  check "remove_error_before" (Some(Error()) = Mem_region.get x (bv 4));
  check "remove_none1" (None = Mem_region.get x (bv 5));
  check "remove_none2" (None = Mem_region.get x (bv 24));
  check "remove_error_after1" (Some(Error()) = Mem_region.get x (bv 25));
  check "remove_error_after2" (None = Mem_region.get x (bv 26))

let test_mark_error () =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "One" ~pos:(bv 0) ~size:(bv 10) in
  let x = Mem_region.mark_error x ~pos:(bv 5) ~size:(bv 10) in
  check "mark_error1" (Some(Error()) = Mem_region.get x (bv 0));
  check "mark_error2" (Some(Error()) = Mem_region.get x (bv 14));
  check "mark_error3" (None = Mem_region.get x (bv 15))

let test_merge () =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "One" ~pos:(bv 0) ~size:(bv 10) in
  let x = Mem_region.add x "Two" ~pos:(bv 15) ~size:(bv 5) in
  let x = Mem_region.add x "Three" ~pos:(bv 25) ~size:(bv 5) in
  let y = Mem_region.empty () in
  let y = Mem_region.add y "One" ~pos:(bv 1) ~size:(bv 10) in
  let y = Mem_region.add y "Two" ~pos:(bv 15) ~size:(bv 5) in
  let y = Mem_region.add y "Four" ~pos:(bv 25) ~size:(bv 5) in
  let merge_fn a b = if a = b then Some(Ok(a)) else Some(Error()) in
  let z = Mem_region.merge x y ~data_merge:merge_fn in
  check "merge_intersect" (Some(Error()) = Mem_region.get z (bv 0));
  check "merge_match_ok" (Some(Ok("Two")) = Mem_region.get z (bv 15));
  check "merge_match_error" (Some(Error()) = Mem_region.get z (bv 25))

let test_equal () =
  let bv num = Bitvector.of_int num ~width:32 in
  let x = Mem_region.empty () in
  let x = Mem_region.add x "One" ~pos:(bv 0) ~size:(bv 10) in
  let x = Mem_region.add x "Two" ~pos:(bv 15) ~size:(bv 5) in
  let y = Mem_region.empty () in
  let y = Mem_region.add y "Two" ~pos:(bv 15) ~size:(bv 5) in
  check "equal_no" (false = (Mem_region.equal x y ~data_equal:(fun x y -> x = y)));
  let y = Mem_region.add y "One" ~pos:(bv 0) ~size:(bv 10) in
  check "equal_yes" (Mem_region.equal x y ~data_equal:(fun x y -> x = y))


let tests = [
  "Add", `Quick, test_add;
  "Negative Indices", `Quick, test_minus;
  "Remove", `Quick, test_remove;
  "Mark_error", `Quick, test_mark_error;
  "Merge", `Quick, test_merge;
  "Equal", `Quick, test_equal;
]
