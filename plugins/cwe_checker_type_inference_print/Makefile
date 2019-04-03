all:
	bapbuild -pkgs yojson,unix,ppx_jane,cwe_checker_core cwe_checker_type_inference_print.plugin
	bapbundle install cwe_checker_type_inference_print.plugin

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker_type_inference_print.plugin
