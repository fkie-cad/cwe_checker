(** This module implements a check for CWE-243: Creation of chroot Jail Without Changing Working Directory.

    Creating a chroot Jail without changing the working directory afterwards does
    not prevent access to files outside of the jail.

    See {: https://cwe.mitre.org/data/definitions/243.html} for detailed a description.

    {1 How the check works}

    According to {: http://www.unixwiz.net/techtips/chroot-practices.html}, there are
    several ways to achieve the safe creation of a chroot jail, e.g. chdir -> chroot -> setuid.
    They are configurable in config.json. We check whether each function that calls
    chroot is using one of these safe call sequences to do so. If not, a warning is emitted.

    {1 False Positives}

    None known.

    {1 False Negatives}

    None known.
*)

val name : string
val version : string

val check_cwe : Bap.Std.program Bap.Std.term -> Bap.Std.project -> Bap.Std.word Bap.Std.Tid.Map.t -> string list list -> string list -> unit
