all:
	bapbundle remove unit_tests_cwe_checker.plugin
	bapbuild -r -Is analysis,checkers,utils unit_tests_cwe_checker.plugin -pkgs alcotest,yojson,unix,ppx_jane,cwe_checker_core
	bapbundle install unit_tests_cwe_checker.plugin
	bap tmp/arrays_x86_64-w64-mingw32_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_i686-w64-mingw32_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_x86_clang.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_arm_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_mips64_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_powerpc_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=Cconv
	bap tmp/arrays_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=MemRegion,TypeInference,CWE476
	bap tmp/c_constructs_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=CWE560,AddrTrans
	bapbundle remove unit_tests_cwe_checker.plugin

clean:
	bapbuild -clean
