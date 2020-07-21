all:
	bapbuild -pkgs yojson,unix,ppx_jane,cwe_checker_core cwe_checker_pointer_inference_debug.plugin
	bapbundle install cwe_checker_pointer_inference_debug.plugin

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker_pointer_inference_debug.plugin
