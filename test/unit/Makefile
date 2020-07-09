all:
	bapbundle remove unit_tests_cwe_checker.plugin
	bapbuild -r -Is analysis,checkers,utils unit_tests_cwe_checker.plugin -pkgs alcotest,yojson,unix,ppx_jane,cwe_checker_core
	bapbundle install unit_tests_cwe_checker.plugin
	bap tmp/arrays_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=MemRegion,Cconv,TypeInference,CWE476
	bap tmp/c_constructs_gcc.out --pass=unit-tests-cwe-checker --unit-tests-cwe-checker-tests=CWE560,AddrTrans
	bapbundle remove unit_tests_cwe_checker.plugin

clean:
	bapbuild -clean
