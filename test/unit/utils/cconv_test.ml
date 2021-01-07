open Bap.Std
open Core_kernel
open Cwe_checker_core

open Cconv

let check msg x = Alcotest.(check bool) msg true x

let example_project = ref None

let example_cconv = ref None

let example_arch = ref None

let example_bin_format = ref None


let test_callee_saved () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let arch = Option.value_exn !example_arch in
  let cconv = Option.value !example_cconv  ~default: "" in
  let bin_format = Option.value_exn !example_bin_format in
  match cconv with
  | "cdecl" | "fastcall" | "stdcall" | "ms" -> begin
      let register = Var.create "EBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "callee_saved_register" (is_callee_saved register project) in
      let register = Var.create "EAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "caller_saved_register" (Bool.(=) (is_callee_saved register project) false) in
      ()
  end
  | "" -> begin
    match arch with
    | "x86_64" -> begin
        match bin_format with
        | "pe" -> begin
            let register = Var.create "RDI" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "callee_saved_register" (is_callee_saved register project) in
            let register = Var.create "R8" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "caller_saved_register" (Bool.(=) (is_callee_saved register project) false) in
            ()
        end
        | "elf" -> begin
            let register = Var.create "RBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "callee_saved_register" (is_callee_saved register project) in
            let register = Var.create "RDI" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "caller_saved_register" (Bool.(=) (is_callee_saved register project) false) in
            ()
        end
        | _ -> failwith "Not a valid binary format"
      end
    | "mips" | "mipsel" | "mips64" | "mips64el" -> begin
        let register = Var.create "S0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "A0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (Bool.(=) (is_callee_saved register project) false) in
        ()
    end
    | "armv4" | "armv5" | "armv6" | "armv7" | "armv4eb" | "armv5eb"
    | "armv6eb" | "armv7eb" | "thumbv4" | "thumbv5" | "thumbv6" | "thumbv7"
    | "thumbv4eb" | "thumbv5eb" | "thumbv6eb" | "thumbv7eb" -> begin
        let register = Var.create "R4" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "R0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (Bool.(=) (is_callee_saved register project) false) in
        ()
    end
    | "aarch64" -> begin
        let register = Var.create "X18" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "X0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (Bool.(=) (is_callee_saved register project) false) in
        ()
    end
    | "powerpc" -> begin
        let register = Var.create "R14" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "R4" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (Bool.(=) (is_callee_saved register project) false) in
        ()
    end
    | "powerpc64" | "powerpc64le" -> begin
        let register = Var.create "R14" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (is_callee_saved register project) in
        let register = Var.create "R10" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "callee_saved_register" (Bool.(=) (is_callee_saved register project) false) in
        ()
    end
    | _ -> failwith "Not a supported architecture"
  end
  | _ -> failwith "Not a supported calling convention"


let test_parameter_register () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let arch = Option.value_exn !example_arch in
  let cconv = Option.value !example_cconv  ~default: "" in
  let bin_format = Option.value_exn !example_bin_format in
  match cconv with
  | "cdecl" | "stdcall" | "ms" -> begin
      let register = Var.create "EBX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
      let register = Var.create "EAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
      ()
    end
  | "fastcall" -> begin
      let register = Var.create "EDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "parameter_register" (is_parameter_register register project) in
      let register = Var.create "ECX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "parameter_register" (is_parameter_register register project) in
      ()
  end
  | "" -> begin
    match arch with
    | "x86_64" -> begin
        match bin_format with
        | "pe" -> begin
            let register = Var.create "R8" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "parameter_register" (is_parameter_register register project) in
            let register = Var.create "RDI" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
            ()
        end
        | "elf" -> begin
            let register = Var.create "RDI" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "parameter_register" (is_parameter_register register project) in
            let register = Var.create "RBP" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
            ()
        end
        | _ -> failwith "Not a valid binary format"
      end
    | "mips" | "mipsel" | "mips64" | "mips64el" -> begin
        let register = Var.create "A3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (is_parameter_register register project) in
        let register = Var.create "V0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
        ()
    end
    | "aarch64" -> begin
        let register = Var.create "X2" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (is_parameter_register register project) in
        let register = Var.create "X23" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
        ()
    end
    | "armv4" | "armv5" | "armv6" | "armv7" | "armv4eb" | "armv5eb"
    | "armv6eb" | "armv7eb" | "thumbv4" | "thumbv5" | "thumbv6" | "thumbv7"
    | "thumbv4eb" | "thumbv5eb" | "thumbv6eb" | "thumbv7eb" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (is_parameter_register register project) in
        let register = Var.create "LR" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
        ()
    end
    | "powerpc" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (is_parameter_register register project) in
        let register = Var.create "F1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
        ()
    end
    | "powerpc64" | "powerpc64le" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (is_parameter_register register project) in
        let register = Var.create "R31" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "parameter_register" (Bool.(=) (is_parameter_register register project) false) in
        ()
    end
    | _ -> failwith "Not a supported architecture"
  end
  | _ -> failwith "Not a supported calling convention"


let test_return_register () =
  (* this test assumes, that the example project is a x64 binary *)
  let project = Option.value_exn !example_project in
  let arch = Option.value_exn !example_arch in
  let cconv = Option.value !example_cconv  ~default: "" in
  let bin_format = Option.value_exn !example_bin_format in
  match cconv with
  | "cdecl" | "fastcall" | "stdcall" | "ms" -> begin
      let register = Var.create "EDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "return_register" (is_return_register register project) in
      let register = Var.create "EBP" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
      let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
      ()
  end
  | "" -> begin
    match arch with
    | "x86_64" -> begin
        match bin_format with
        | "pe" -> begin
            let register = Var.create "RAX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "return_register" (is_return_register register project) in
            let register = Var.create "RDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
            ()
        end
        | "elf" -> begin
            let register = Var.create "RDX" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "return_register" (is_return_register register project) in
            let register = Var.create "R12" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
            let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
            ()
        end
        | _ -> failwith "Not a valid binary format"
    end
    | "mips" | "mipsel" | "mips64" | "mips64el" -> begin
        let register = Var.create "V0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "return_register" (is_return_register register project) in
        let register = Var.create "A0" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
        ()
    end
    | "aarch64" -> begin
        let register = Var.create "X1" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "return_register" (is_return_register register project) in
        let register = Var.create "X30" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
        ()
    end
    | "armv4" | "armv5" | "armv6" | "armv7" | "armv4eb" | "armv5eb"
    | "armv6eb" | "armv7eb" | "thumbv4" | "thumbv5" | "thumbv6" | "thumbv7"
    | "thumbv4eb" | "thumbv5eb" | "thumbv6eb" | "thumbv7eb" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "return_register" (is_return_register register project) in
        let register = Var.create "R4" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
        ()
    end
    | "powerpc" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "return_register" (is_return_register register project) in
        let register = Var.create "R10" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
        ()
    end
    | "powerpc64" | "powerpc64le" -> begin
        let register = Var.create "R3" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "return_register" (is_return_register register project) in
        let register = Var.create "R25" (Bil.Imm (Symbol_utils.arch_pointer_size_in_bytes project * 8)) in
        let () = check "no_return_register" (Bool.(=) (is_return_register register project) false) in
        ()
    end
    | _ -> failwith "Not a supported architecture"
  end
  | _ -> failwith "Not a supported calling convention"


let test_extract_bin_format () =
  let project = Option.value_exn !example_project in
  let () = check "bin_format" (Poly.(=) (extract_bin_format project) (Option.value_exn !example_bin_format)) in
  ()


let tests = [
  "Callee saved register", `Quick, test_callee_saved;
  "Parameter register", `Quick, test_parameter_register;
  "Return register", `Quick, test_return_register;
  "Extract bin format", `Quick, test_extract_bin_format;
]
