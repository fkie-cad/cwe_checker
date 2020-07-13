open Bap.Std
open Core_kernel


val example_project: Project.t option ref

val example_cconv: string option ref

val example_arch: string option ref

val tests: unit Alcotest.test_case list
