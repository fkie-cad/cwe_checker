all:
	bapbundle remove cwe_checker_unit_tests.plugin
	bapbuild cwe_checker_unit_tests.plugin -Is analysis,src,src/utils,src/analysis,src/checkers -pkgs core,alcotest,yojson,unix,ppx_jane
	bapbundle install cwe_checker_unit_tests.plugin
	bap ../artificial_samples/build/arrays_x64.out --pass=cwe-checker-unit-tests
	bapbundle remove cwe_checker_unit_tests.plugin
