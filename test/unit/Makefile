all:
	bapbundle remove cwe_checker_unit_tests.plugin
	bapbuild -r -Is analysis cwe_checker_unit_tests.plugin -pkgs core,alcotest,yojson,unix,ppx_jane,cwe_checker_core
	bapbundle install cwe_checker_unit_tests.plugin
	bap ../artificial_samples/build/arrays_x64.out --pass=cwe-checker-unit-tests
	bapbundle remove cwe_checker_unit_tests.plugin

clean:
	bapbuild -clean
