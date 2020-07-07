open Bap.Std

let name = "Memory"
let version = "0.1"

let check_cwe (_program: Program.t) (project: Project.t) (tid_map: word Tid.Map.t) (_: string list list) (_: string list) =
  Pointer_inference.run project tid_map
