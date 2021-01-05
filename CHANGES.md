0.4 (2021-01)
====

-   Added a lot more test cases to acceptance tests (PR #46)
-   Reworked CWE-476 check to track stack variables (PR #47)
-   Switched to BAP 2.0 (PR #49)
-   Several internal code improvements (PRs #51, #58, #62, #67)
-   Added deprecation warnings to the emulation based checks (PR #66)
-   Added a new (still experimental) engine for data-flow analysis written in Rust (PR #70)
-   Added new, data-flow based checks for CWEs 415 and 416 (PR #70)
-   Several code improvements to for the CWE 415 and 416 checks (PRs #76, #77. #78, #84)
-   Report more accurate incident locations for CWE 476 (PR #80)
-   Enable Ghidra as an alternative Backend to BAP (still experimental) (PRs #86, #87)
-   Added acceptance tests for the Ghidra backend (PRs #91, #99)
-   Bugfixes for the Ghidra backend (PRs #98, #101, #104, #106, #110, #114, #120)
-   Ported the CWE checks to Rust for the Ghidra backend (PRs #88, #95, #100, #102, #111, #117, #119, #121)
-   Added support for Ghidra 9.2 (PR #116)

0.3 (2019-12)
====

-   Added more documentation to checks (PR #26)
-   Added clang as another compiler for test cases, added tests for clang compiled test cases (PR #27)
-   Fixed check CWE367: use symbols defined in config.json (PR #28)
-   Refactoring of logging and JSON support via --json (PR #30)
-   Added file output support via --out (PR #30)
-   Surpress logging of info, error and warning to STDOUT via --no-logging (PR #32)
-   Added check-path feature via --check-path that searches paths between interesting input functions and cwe hits (PR #31)
-   Added online documentation (PR #36, #37)
-   Added convenience executable to enable shorter command line options (PR #40)
-   Added a plugin for integration into Ghidra (PR #42, #43)

0.2 (2019-06-25)
=====

-   Refactoring: Unification of cwe_checker function interface
-   Refactoring: Created utils module for JSON functionality
-   Added check for CWE 248: Uncaught Exception (PR #5)
-   Added automated test suite (run with make test) (PR #7)
-   Improved cross compiling for acceptance test cases by using dockcross (PR #8)
-   Added BAP recipe for standard cwe_checker run (PR #9)
-   Improved check for CWE-476 (NULL Pointer Dereference) using data flow analysis (PR #11)
-   Added cwe_checker_emulation plugin based on BAP's Primus to detect CWE-125, CWE-415, and CWE-416 (PR #15)
-   Switched C build system from make to scons (PR #16)
-   Added type inference pass (PR #14, #18)
-   Added unit tests to test suite (PR #14)
-   Added check for CWE-560 (Use of umask() with chmod-style Argument) (PR #21)

0.1 (2018-10-08)
=====

Initial release of cwe_checker.
