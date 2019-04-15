open Bap.Std
open Core_kernel
open Cwe_checker_core

let () = Project.register_pass Type_inference.compute_pointer_register
