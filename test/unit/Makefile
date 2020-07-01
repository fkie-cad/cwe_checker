all:
	bapbundle remove unit_tests_cwe_checker.plugin
	bapbuild -r -Is analysis,checkers,utils unit_tests_cwe_checker.plugin -pkgs alcotest,yojson,unix,ppx_jane,cwe_checker_core
	bapbundle install unit_tests_cwe_checker.plugin
	bap ../artificial_samples/build/arrays_x64_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-partial=Cconv,TypeInference,CWE476
	bap ../artificial_samples/build/c_constructs_x64_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-partial=CWE560,AddrTrans
	bapbundle remove unit_tests_cwe_checker.plugin

clean:
	bapbuild -clean
