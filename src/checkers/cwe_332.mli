(** This module implements a check for CWE332: Insufficient Entropy in PRNG.

    This can happen, for instance, if the PRNG is not seeded. A classical example
    would be calling rand without srand. This could lead to predictable random
    numbers and could, for example, weaken crypto functionality.

    See {: https://cwe.mitre.org/data/definitions/332.html} for a detailed description.

    {1 How the check works}

    We check whether the program calls rand but not srand.

    {1 False Positives}

    - The program could use rand for non-cryptographic purposes.

    {1 False Negatives}

    - It is not checked whether srand gets called before rand
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> 'a -> 'b -> string list list -> 'c -> unit
