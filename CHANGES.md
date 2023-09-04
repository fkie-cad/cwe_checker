0.8-dev
===

-   Improve logic and context information generation of CWE-416 (use-after-free) check (PRs #423, #429)

0.7 (2023-06)
====

-   Improve handling of conditional assignment assembly instructions (PR #337)
-   Improved exactness of CWE-190 check (PR #336)
-   Improved exactness of CWE-119 check (PRs #339, #399)
-   Added stubs for common libC-functions to several analyses (PRs #342, #348)
-   Added a check for CWE-789: Memory Allocation with Excessive Size Value (PR #347)
-   Improved implementation of the expression propagation algorithm (PR #356)
-   Implement tracking of variables in global memory for several analyses (PRs #358, #361)
-   Generate call trace information in the JSON output of CWE-119-check results (PRs #365, #388)
-   Add macros for simpler unit test generation, refactored unit tests (PRs #380, #386)
-   Function signature analysis output now gets properly sanitized (PR #389)
-   Migrate the official Docker images from Dockerhub to ghcr.io (PR #401)
-   Improved support for MIPS (PR #404)
-   Generate call trace information in the JSON output of CWE-416-check results (PR #408)
-   Support more allocation/deallocation functions in the checks, e.g C++-new/delete (PR #414)

0.6 (2022-06)
====

-   Add support for analysis of bare-metal binaries (PR #203)
-   Improve expressiveness of DataDomain (PRs #209, #211)
-   Add `--statistics` and `--verbose` commandline flags (PRs #210, #216)
-   Improve handling of MIPS binaries (PR #213)
-   Sort generated CWE warnings by address (PR #221)
-   Publish Docker images on ghcr.io in addition to Dockerhub (PR #222, #225)
-   Correctly classify some CWEs as Null dereferences instead of buffer overflows (PR #226)
-   Implement abstract domains for strings and rewrite CWE-78 check using them (PR #235)
-   Updated dependencies (PRs #206, #264, #266, #282)
-   Implement function signature analysis (PR #267, #277)
-   Update cwe_checker_to_ida script (PRs #279, #281)
-   New installer script that can search for the Ghidra installation path for you (PR #278)
-   Refactor handling of caller stacks in PointerInference analysis (PR #287)
-   Project struct refactorings (PRs #291, #301, #324)
-   New improved implementation of CWE-416 Use-After-Free check (PRs #311, #318, #328)
-   New improved implementation of CWE-119 Buffer Overflow check (PRs #315, #326, #328, #333)
-   Use information on non-returning functions in CFG generation (PR #319)
-   Handle stack manipulation based on stack alignment for x86 (PRs #317, #323)

0.5 (2021-07)
====

-   Switched default backend to Ghidra (PR #128)
-   Handle global memory accesses during analysis (PRs #131, #133)
-   Improvements to the Docker image (PR #134)
-   Add OS Command Injection Check (PRs #130, #154, #167, #182, #184, #187)
-   Remove deprecated BAP backend (PRs #148, #149, #150)
-   Implement abstract strided interval domain (PRs #152, #158, #166, #189)
-   Add Buffer Overflow checks (PRs #159, #174)
-   Prevent duplication of warnings in CWE-415 and CWE-416 checks (#183)
-   Implement expression propagation to improve disassembler output (#185)

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
-   Added support for Ghidra 9.2 (PR #116) and BAP 2.2 (PR #122)

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
