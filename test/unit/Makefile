all:
	bapbundle remove cwe_checker_unit_tests.plugin
	bapbuild -r -Is analysis,checkers,utils cwe_checker_unit_tests.plugin -pkgs alcotest,yojson,unix,ppx_jane,cwe_checker_core
	bapbundle install cwe_checker_unit_tests.plugin
	bap ../artificial_samples/build/arrays_x64_gcc.out --pass=cwe-checker-unit-tests --cwe-checker-unit-tests-partial=Cconv
	bapbundle remove cwe_checker_unit_tests.plugin

clean:
	bapbuild -clean
